"""Self-service password establishment and recovery over email OTP."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from compass.audit.context import AuditContext
from compass.audit.services import record_event
from compass.authentication.abuse import (
    AuthenticationRateLimited,
    check_auth_rate_limit,
    request_ip,
)
from compass.authentication.actions import AUTH_PASSWORD_INITIAL_SET, AUTH_PASSWORD_RESET
from compass.authentication.email_otp import (
    EmailOTPSecurityUnavailable,
    _consume_email_otp_locked,
    _verify_email_otp_locked,
    issue_email_otp,
)
from compass.authentication.models import EmailOTPChallenge, EmailOTPPurpose
from compass.authentication.security import invalidate_reusable_auth_state

User = get_user_model()

PASSWORD_ACCESS_METHOD = "email_otp"
PASSWORD_ACCESS_PURPOSE = EmailOTPPurpose.RECOVERY
PASSWORD_ACCESS_MESSAGE = "If the account is eligible, a security code has been sent."
PASSWORD_CHALLENGE_INVALID_MESSAGE = (
    "The security code could not be verified or is no longer valid."
)
PASSWORD_POLICY_MESSAGE = "The new password does not meet the password policy."
MAX_PASSWORD_LENGTH = 1_024


class PasswordAccessError(RuntimeError):
    """Base class for expected password-access failures."""


class InvalidPasswordAccessRequest(PasswordAccessError):
    """The anonymous password-access request cannot be accepted as input."""


class PasswordChallengeInvalid(PasswordAccessError):
    """The submitted password challenge is unavailable or cannot be completed."""


@dataclass(frozen=True, slots=True)
class PasswordPolicyIssue:
    """A safe, frontend-facing password-policy issue with no submitted secret."""

    message: str
    type: str

    def as_dict(self) -> dict[str, object]:
        return {
            "loc": ["new_password"],
            "message": self.message,
            "type": self.type,
        }


class PasswordPolicyRejected(PasswordAccessError):
    """The proposed password failed the configured Django password policy."""

    def __init__(self, issues: tuple[PasswordPolicyIssue, ...]) -> None:
        super().__init__(PASSWORD_POLICY_MESSAGE)
        self.issues = issues


@dataclass(frozen=True, slots=True)
class PasswordAccessRequestResult:
    challenge: EmailOTPChallenge


@dataclass(frozen=True, slots=True)
class PasswordAccessConfirmResult:
    password_set: bool
    action: str


def _normalize_email(email: str) -> str:
    try:
        return User.objects.clean_email(email)
    except (TypeError, ValueError) as exc:
        raise InvalidPasswordAccessRequest("a valid email address is required") from exc


def _password_policy_issues(exc: ValidationError) -> tuple[PasswordPolicyIssue, ...]:
    issues: list[PasswordPolicyIssue] = []
    for error in exc.error_list:
        code = error.code if isinstance(error.code, str) and error.code else "password_invalid"
        for message in error.messages:
            issues.append(PasswordPolicyIssue(message=str(message), type=code))
    return tuple(issues)


def _validate_new_password(*, user, new_password: str) -> None:
    if len(new_password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyRejected(
            (
                PasswordPolicyIssue(
                    message=(
                        f"The new password must be no longer than {MAX_PASSWORD_LENGTH} characters."
                    ),
                    type="max_length",
                ),
            )
        )
    if user.has_usable_password() and user.check_password(new_password):
        raise PasswordPolicyRejected(
            (
                PasswordPolicyIssue(
                    message="Choose a new password that is different from your current password.",
                    type="password_reuse",
                ),
            )
        )
    try:
        validate_password(new_password, user=user)
    except ValidationError as exc:
        raise PasswordPolicyRejected(_password_policy_issues(exc)) from None


def request_password_access(
    *,
    email: str,
    request=None,
    limiter=None,
    turnstile_token: str | None = None,
    now: datetime | None = None,
) -> PasswordAccessRequestResult:
    """Issue one real or decoy recovery challenge without account enumeration."""

    normalized_email = _normalize_email(email)
    current = now or timezone.now()
    with transaction.atomic():
        user = User.objects.select_for_update().filter(email=normalized_email).first()
        eligible = user is not None and user.is_active
        issue = issue_email_otp(
            email=normalized_email,
            purpose=PASSWORD_ACCESS_PURPOSE,
            user=user if eligible else None,
            request=request,
            limiter=limiter,
            turnstile_token=turnstile_token,
            dispatch=eligible,
            replace_existing=True,
            now=current,
        )
    return PasswordAccessRequestResult(challenge=issue.challenge)


def _challenge_identifier(challenge_id, existing: EmailOTPChallenge | None) -> str:
    return existing.email if existing is not None else str(challenge_id)


def confirm_password_access(
    *,
    challenge_id,
    code: str,
    new_password: str,
    request=None,
    limiter=None,
    now: datetime | None = None,
) -> PasswordAccessConfirmResult:
    """Atomically verify one recovery OTP and establish or replace the user password."""

    current = now or timezone.now()
    try:
        existing = EmailOTPChallenge.objects.filter(pk=challenge_id).first()
    except (TypeError, ValueError, ValidationError):
        existing = None
    try:
        check_auth_rate_limit(
            "email_otp_verify",
            ip_address=request_ip(request),
            identifier=_challenge_identifier(challenge_id, existing),
            limiter=limiter,
        )
    except AuthenticationRateLimited:
        raise
    except Exception as exc:
        raise EmailOTPSecurityUnavailable from exc

    invalid = False
    result: PasswordAccessConfirmResult | None = None
    with transaction.atomic():
        locked_user = None
        if existing is not None and existing.user_id is not None:
            locked_user = User.objects.select_for_update().filter(pk=existing.user_id).first()

        challenge = EmailOTPChallenge.objects.select_for_update().filter(pk=challenge_id).first()
        if challenge is not None and challenge.user_id is not None and locked_user is not None:
            challenge.user = locked_user
        if challenge is None:
            invalid = True
        elif not _verify_email_otp_locked(
            challenge=challenge,
            code=code,
            request=request,
            current=current,
            expected_purpose=PASSWORD_ACCESS_PURPOSE,
        ):
            invalid = True
        else:
            user = locked_user
            if (
                user is None
                or challenge.user_id != user.pk
                or not user.is_active
                or challenge.email != user.email
            ):
                _consume_email_otp_locked(
                    challenge=challenge,
                    request=request,
                    current=current,
                )
                invalid = True
            else:
                _validate_new_password(user=user, new_password=new_password)
                initial_password = not user.has_usable_password()
                user.set_password(new_password)
                user.save(update_fields=["password", "updated_at"])
                _consume_email_otp_locked(
                    challenge=challenge,
                    request=request,
                    current=current,
                )
                action = AUTH_PASSWORD_INITIAL_SET if initial_password else AUTH_PASSWORD_RESET
                reason = "password_initial_set" if initial_password else "password_reset"
                context = (
                    AuditContext.from_request(request, actor=user)
                    if request is not None
                    else AuditContext.user(user)
                )
                invalidate_reusable_auth_state(
                    user_id=user.pk,
                    context=context,
                    reason=reason,
                    now=current,
                    email_challenge_purposes=(PASSWORD_ACCESS_PURPOSE,),
                    email_challenge_email=user.email,
                )
                record_event(
                    context=context,
                    action=action,
                    outcome="SUCCESS",
                    target_type="accounts.user",
                    target_id=user.pk,
                    metadata={"method": PASSWORD_ACCESS_METHOD},
                )
                result = PasswordAccessConfirmResult(password_set=True, action=action)

    if invalid or result is None:
        raise PasswordChallengeInvalid(PASSWORD_CHALLENGE_INVALID_MESSAGE)
    return result


__all__ = [
    "InvalidPasswordAccessRequest",
    "MAX_PASSWORD_LENGTH",
    "PASSWORD_ACCESS_MESSAGE",
    "PASSWORD_CHALLENGE_INVALID_MESSAGE",
    "PASSWORD_POLICY_MESSAGE",
    "PasswordAccessConfirmResult",
    "PasswordAccessError",
    "PasswordAccessRequestResult",
    "PasswordChallengeInvalid",
    "PasswordPolicyIssue",
    "PasswordPolicyRejected",
    "confirm_password_access",
    "request_password_access",
]
