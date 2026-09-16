"""Minimal internal email-OTP foundation, distinct from TOTP."""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from compass.audit.context import AuditContext
from compass.audit.models import AuditActorType
from compass.audit.services import record_event
from compass.authentication.abuse import (
    AuthenticationAbuseUnavailable,
    AuthenticationRateLimited,
    check_auth_rate_limit,
    request_ip,
    verify_turnstile,
)
from compass.authentication.actions import (
    AUTH_EMAIL_OTP_CONSUMED,
    AUTH_EMAIL_OTP_FAILED,
    AUTH_EMAIL_OTP_ISSUED,
)
from compass.authentication.models import EmailOTPChallenge, EmailOTPPurpose
from compass.authentication.tasks import deliver_email_otp

EMAIL_OTP_CODE_RE = re.compile(r"^\d{6}$", re.ASCII)


class EmailOTPInvalid(RuntimeError):
    """Raised when an email OTP challenge is missing or cannot be used."""


class EmailOTPResendTooSoon(RuntimeError):
    """Raised when a resend is attempted before the configured cooldown."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("email OTP resend is temporarily unavailable")
        self.retry_after_seconds = max(int(retry_after_seconds), 1)


class EmailOTPResendLimitReached(RuntimeError):
    """Raised when a challenge has exhausted its bounded delivery attempts."""


class EmailOTPSecurityUnavailable(RuntimeError):
    """Raised when required email-OTP abuse controls cannot run."""


@dataclass(frozen=True, slots=True)
class EmailOTPIssue:
    challenge: EmailOTPChallenge

    def __repr__(self) -> str:
        return f"EmailOTPIssue(challenge_id={self.challenge.pk!s})"


def _normalize_email(email: str) -> str:
    if not isinstance(email, str):
        raise ValueError("email must be a string")
    normalized = email.strip().lower()
    if not normalized or len(normalized) > 254:
        raise ValueError("email must be a valid identifier")
    return normalized


def _validate_purpose(purpose: str | EmailOTPPurpose) -> str:
    normalized = purpose.value if isinstance(purpose, EmailOTPPurpose) else purpose
    if normalized not in EmailOTPPurpose.values:
        raise ValueError("unknown email OTP purpose")
    return normalized


def invalidate_email_otp_challenges(
    *,
    user_id=None,
    email: str | None = None,
    purposes: Iterable[str | EmailOTPPurpose] | None = None,
    now: datetime | None = None,
) -> int:
    """Invalidate outstanding email challenges without deleting their hash-only records."""

    if user_id is None and email is None:
        raise ValueError("user_id or email is required")
    current = now or timezone.now()
    filters = Q(consumed_at__isnull=True)
    if user_id is not None and email is not None:
        filters &= Q(user_id=user_id) | Q(email=_normalize_email(email))
    elif user_id is not None:
        filters &= Q(user_id=user_id)
    else:
        filters &= Q(email=_normalize_email(email))
    if purposes is not None:
        normalized_purposes = tuple(_validate_purpose(purpose) for purpose in purposes)
        if not normalized_purposes:
            return 0
        filters &= Q(purpose__in=normalized_purposes)

    count = 0
    challenges = EmailOTPChallenge.objects.select_for_update().filter(filters)
    for challenge in challenges:
        challenge.consumed_at = current
        challenge.save(update_fields=["consumed_at"])
        count += 1
    return count


def _new_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _context(*, request, user) -> AuditContext:
    if request is not None:
        return AuditContext.from_request(
            request,
            actor=user,
            actor_type=AuditActorType.USER if user is not None else AuditActorType.ANONYMOUS,
        )
    return AuditContext.user(user) if user is not None else AuditContext.anonymous()


def _enqueue_delivery(challenge_id: str, code: str) -> None:
    try:
        deliver_email_otp.delay(challenge_id, code)
    except Exception:
        # The code is deliberately not part of this log record. A later resend can issue a new
        # code, while the challenge itself remains hash-only in PostgreSQL.
        import logging

        logging.getLogger("compass.authentication.email_otp").exception(
            "email OTP delivery could not be queued",
            extra={"event": "email_otp_delivery_enqueue_failed", "challenge_id": challenge_id},
        )


def issue_email_otp(
    *,
    email: str,
    purpose: str | EmailOTPPurpose,
    user=None,
    request=None,
    limiter=None,
    turnstile_token: str | None = None,
    dispatch: bool = True,
    replace_existing: bool = False,
    now: datetime | None = None,
) -> EmailOTPIssue:
    """Create an email OTP without exposing its plaintext to callers or persistence.

    ``replace_existing`` is used by password access so that one account/email has only one
    outstanding challenge for the selected purpose. The replacement and insert occur in the
    same transaction; callers that need account-level serialization should lock the user row
    before calling this function.
    """

    normalized_email = _normalize_email(email)
    normalized_purpose = _validate_purpose(purpose)
    ip_address = request_ip(request)
    try:
        check_auth_rate_limit(
            "email_otp_issue",
            ip_address=ip_address,
            identifier=normalized_email,
            limiter=limiter,
        )
    except AuthenticationRateLimited:
        raise
    except AuthenticationAbuseUnavailable as exc:
        raise EmailOTPSecurityUnavailable from exc
    if not verify_turnstile(request, turnstile_token, flow="email_otp"):
        raise EmailOTPInvalid("email OTP security verification failed")

    current = now or timezone.now()
    code = _new_code()
    with transaction.atomic():
        locked_user = user if getattr(user, "pk", None) else None
        if replace_existing:
            if locked_user is not None:
                locked_user = type(locked_user).objects.select_for_update().get(pk=locked_user.pk)
            invalidate_email_otp_challenges(
                user_id=locked_user.pk if locked_user is not None else None,
                email=normalized_email,
                purposes=(normalized_purpose,),
                now=current,
            )
        challenge = EmailOTPChallenge.objects.create(
            user=locked_user,
            email=normalized_email,
            purpose=normalized_purpose,
            code_hash=make_password(code),
            created_at=current,
            expires_at=current + timedelta(seconds=settings.AUTH_EMAIL_OTP_TTL_SECONDS),
            last_sent_at=current,
            send_count=1,
            request_id=getattr(request, "request_id", None),
        )
        record_event(
            context=_context(request=request, user=locked_user),
            action=AUTH_EMAIL_OTP_ISSUED,
            outcome="SUCCESS",
            target_type="auth.emailotp",
            target_id=challenge.pk,
            metadata={"purpose": normalized_purpose},
        )
        if dispatch:
            transaction.on_commit(lambda: _enqueue_delivery(str(challenge.pk), code))
    return EmailOTPIssue(challenge=challenge)


def resend_email_otp(
    *,
    challenge_id,
    request=None,
    limiter=None,
    turnstile_token: str | None = None,
    now: datetime | None = None,
) -> EmailOTPIssue:
    current = now or timezone.now()
    existing = EmailOTPChallenge.objects.select_related("user").filter(pk=challenge_id).first()
    if existing is None:
        raise EmailOTPInvalid("email OTP challenge is unavailable")
    try:
        check_auth_rate_limit(
            "email_otp_resend",
            ip_address=request_ip(request),
            identifier=existing.email,
            limiter=limiter,
        )
    except AuthenticationRateLimited:
        raise
    except AuthenticationAbuseUnavailable as exc:
        raise EmailOTPSecurityUnavailable from exc
    if not verify_turnstile(request, turnstile_token, flow="email_otp"):
        raise EmailOTPInvalid("email OTP security verification failed")

    code = _new_code()
    with transaction.atomic():
        challenge = EmailOTPChallenge.objects.select_for_update().get(pk=challenge_id)
        if challenge.consumed_at is not None:
            raise EmailOTPInvalid("email OTP challenge is unavailable")
        elapsed = (current - challenge.last_sent_at).total_seconds()
        if elapsed < settings.AUTH_EMAIL_OTP_RESEND_INTERVAL_SECONDS:
            raise EmailOTPResendTooSoon(
                settings.AUTH_EMAIL_OTP_RESEND_INTERVAL_SECONDS - int(elapsed)
            )
        if challenge.send_count >= settings.AUTH_EMAIL_OTP_MAX_SENDS:
            raise EmailOTPResendLimitReached("email OTP resend limit reached")
        challenge.code_hash = make_password(code)
        challenge.created_at = current
        challenge.expires_at = current + timedelta(seconds=settings.AUTH_EMAIL_OTP_TTL_SECONDS)
        challenge.failed_attempt_count = 0
        challenge.send_count += 1
        challenge.last_sent_at = current
        challenge.save(
            update_fields=[
                "code_hash",
                "created_at",
                "expires_at",
                "failed_attempt_count",
                "send_count",
                "last_sent_at",
            ]
        )
        record_event(
            context=_context(request=request, user=challenge.user),
            action=AUTH_EMAIL_OTP_ISSUED,
            outcome="SUCCESS",
            target_type="auth.emailotp",
            target_id=challenge.pk,
            metadata={"purpose": challenge.purpose, "resend": True},
        )
        transaction.on_commit(lambda: _enqueue_delivery(str(challenge.pk), code))
    return EmailOTPIssue(challenge=challenge)


def consume_email_otp(
    *, challenge_id, code: str, request=None, limiter=None, now: datetime | None = None
) -> EmailOTPChallenge:
    """Consume one valid email OTP; invalid attempts are bounded and audited without the code."""

    current = now or timezone.now()
    existing = EmailOTPChallenge.objects.select_related("user").filter(pk=challenge_id).first()
    if existing is None:
        raise EmailOTPInvalid("email OTP challenge is unavailable")
    try:
        check_auth_rate_limit(
            "email_otp_verify",
            ip_address=request_ip(request),
            identifier=existing.email,
            limiter=limiter,
        )
    except AuthenticationRateLimited:
        raise
    except AuthenticationAbuseUnavailable as exc:
        raise EmailOTPSecurityUnavailable from exc

    invalid = False
    with transaction.atomic():
        challenge = EmailOTPChallenge.objects.select_for_update().get(pk=challenge_id)
        valid = _verify_email_otp_locked(
            challenge=challenge,
            code=code,
            request=request,
            current=current,
        )
        if not valid:
            invalid = True
        else:
            _consume_email_otp_locked(
                challenge=challenge,
                request=request,
                current=current,
            )
    if invalid:
        raise EmailOTPInvalid("email OTP challenge is unavailable")
    return challenge


def _verify_email_otp_locked(
    *,
    challenge: EmailOTPChallenge,
    code: str,
    request=None,
    current: datetime,
    expected_purpose: str | EmailOTPPurpose | None = None,
) -> bool:
    """Verify a locked challenge without consuming a valid code.

    This is intentionally private and only safe while the caller owns the challenge row lock
    inside an outer transaction. Invalid attempts are still counted and audited here so generic
    OTP consumption and password completion share exactly one verification implementation.
    """

    normalized_purpose = (
        _validate_purpose(expected_purpose) if expected_purpose is not None else None
    )
    context = _context(request=request, user=challenge.user)
    normalized = code.strip() if isinstance(code, str) else ""
    candidate = normalized if EMAIL_OTP_CODE_RE.fullmatch(normalized) else ""
    usable = (
        challenge.consumed_at is None
        and challenge.expires_at > current
        and challenge.failed_attempt_count < settings.AUTH_EMAIL_OTP_MAX_ATTEMPTS
        and (normalized_purpose is None or challenge.purpose == normalized_purpose)
    )
    valid = usable and check_password(candidate, challenge.code_hash)
    if valid:
        return True

    if usable:
        challenge.failed_attempt_count += 1
        challenge.save(update_fields=["failed_attempt_count"])
    record_event(
        context=context,
        action=AUTH_EMAIL_OTP_FAILED,
        outcome="DENIED",
        target_type="auth.emailotp",
        target_id=challenge.pk,
        metadata={"purpose": challenge.purpose},
    )
    return False


def _consume_email_otp_locked(
    *, challenge: EmailOTPChallenge, request=None, current: datetime
) -> None:
    """Consume a verified challenge while its row lock is held."""

    if challenge.consumed_at is not None:
        raise EmailOTPInvalid("email OTP challenge is unavailable")
    challenge.consumed_at = current
    challenge.save(update_fields=["consumed_at"])
    record_event(
        context=_context(request=request, user=challenge.user),
        action=AUTH_EMAIL_OTP_CONSUMED,
        outcome="SUCCESS",
        target_type="auth.emailotp",
        target_id=challenge.pk,
        metadata={"purpose": challenge.purpose},
    )


__all__ = [
    "EmailOTPInvalid",
    "EmailOTPIssue",
    "EmailOTPSecurityUnavailable",
    "EmailOTPResendLimitReached",
    "EmailOTPResendTooSoon",
    "consume_email_otp",
    "invalidate_email_otp_challenges",
    "issue_email_otp",
    "resend_email_otp",
]
