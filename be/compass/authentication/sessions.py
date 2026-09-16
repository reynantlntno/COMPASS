"""Opaque authentication and trusted-session credential services."""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from compass.audit.context import AuditContext, summarize_user_agent
from compass.audit.services import record_event
from compass.authentication.actions import (
    AUTH_SESSION_CREATED,
    AUTH_SESSION_REVOKED,
    AUTH_TRUSTED_SESSION_CREATED,
    AUTH_TRUSTED_SESSION_REVOKED,
)
from compass.authentication.models import AuthSession, LoginChallenge, TrustedSession
from compass.common.correlation import normalize_request_id
from compass.common.rate_limit import client_ip

OPAQUE_TOKEN_BYTES = 32
MAX_COOKIE_TOKEN_LENGTH = 512


class RecentMFARequired(RuntimeError):
    """Raised when a sensitive action needs a recent MFA assertion."""


@dataclass(frozen=True, slots=True)
class IssuedSession:
    token: str
    session: AuthSession

    def __repr__(self) -> str:
        return f"IssuedSession(session_id={self.session.pk!s})"


@dataclass(frozen=True, slots=True)
class IssuedTrustedSession:
    token: str
    session: TrustedSession

    def __repr__(self) -> str:
        return f"IssuedTrustedSession(session_id={self.session.pk!s})"


@dataclass(frozen=True, slots=True)
class IssuedLoginChallenge:
    token: str
    challenge: LoginChallenge

    def __repr__(self) -> str:
        return f"IssuedLoginChallenge(challenge_id={self.challenge.pk!s})"


def generate_opaque_token() -> str:
    """Generate a URL-safe credential with 256 bits of randomness."""

    return secrets.token_urlsafe(OPAQUE_TOKEN_BYTES)


def digest_opaque_token(token: str) -> str:
    """Return the only database representation used for an opaque credential."""

    if not isinstance(token, str) or not token or len(token) > MAX_COOKIE_TOKEN_LENGTH:
        raise ValueError("opaque credential is invalid")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _request_ip(request) -> str | None:
    if request is None:
        return None
    value = client_ip(request)
    if not value or value == "unknown":
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _request_user_agent(request) -> str | None:
    if request is None:
        return None
    return summarize_user_agent(
        request.headers.get("User-Agent") or request.META.get("HTTP_USER_AGENT")
    )


def _request_id(request) -> str | None:
    if request is None:
        return None
    value = getattr(request, "request_id", None)
    return normalize_request_id(str(value)) if value else None


def _touch_if_stale(instance, *, model, request=None, now: datetime) -> None:
    interval = settings.AUTH_SESSION_LAST_USED_WRITE_INTERVAL_SECONDS
    if now - instance.last_used_at < timedelta(seconds=interval):
        return
    updates = {"last_used_at": now}
    ip_address = _request_ip(request)
    if ip_address:
        updates["last_ip_address"] = ip_address
    updated = model.objects.filter(
        pk=instance.pk,
        revoked_at__isnull=True,
        last_used_at=instance.last_used_at,
    ).update(**updates)
    if updated:
        instance.last_used_at = now
        if ip_address:
            instance.last_ip_address = ip_address


def create_auth_session(
    user,
    *,
    request=None,
    mfa_verified_at: datetime | None = None,
    now: datetime | None = None,
    using: str | None = None,
) -> IssuedSession:
    if not getattr(user, "pk", None) or not getattr(user, "is_active", False):
        raise ValueError("only an active saved user can receive a session")
    current = now or timezone.now()
    token = generate_opaque_token()
    manager = AuthSession.objects.using(using) if using else AuthSession.objects
    session = manager.create(
        user=user,
        token_digest=digest_opaque_token(token),
        created_at=current,
        last_used_at=current,
        expires_at=current + timedelta(seconds=settings.AUTH_SESSION_AGE_SECONDS),
        mfa_verified_at=mfa_verified_at,
        user_agent_summary=_request_user_agent(request),
        initial_ip_address=_request_ip(request),
        last_ip_address=_request_ip(request),
        created_request_id=_request_id(request),
    )
    return IssuedSession(token=token, session=session)


def create_trusted_session(
    user,
    *,
    request=None,
    now: datetime | None = None,
    using: str | None = None,
) -> IssuedTrustedSession:
    if not getattr(user, "pk", None) or not getattr(user, "is_active", False):
        raise ValueError("only an active saved user can receive trusted-session state")
    current = now or timezone.now()
    token = generate_opaque_token()
    manager = TrustedSession.objects.using(using) if using else TrustedSession.objects
    session = manager.create(
        user=user,
        token_digest=digest_opaque_token(token),
        created_at=current,
        last_used_at=current,
        expires_at=current + timedelta(seconds=settings.AUTH_TRUSTED_SESSION_AGE_SECONDS),
        user_agent_summary=_request_user_agent(request),
        created_ip_address=_request_ip(request),
        last_ip_address=_request_ip(request),
        created_request_id=_request_id(request),
    )
    return IssuedTrustedSession(token=token, session=session)


def create_login_challenge(
    user,
    *,
    allowed_methods: list[str],
    trust_browser: bool,
    request=None,
    now: datetime | None = None,
    using: str | None = None,
) -> IssuedLoginChallenge:
    if not getattr(user, "pk", None) or not getattr(user, "is_active", False):
        raise ValueError("only an active saved user can receive a login challenge")
    current = now or timezone.now()
    token = generate_opaque_token()
    manager = LoginChallenge.objects.using(using) if using else LoginChallenge.objects
    challenge = manager.create(
        user=user,
        challenge_digest=digest_opaque_token(token),
        created_at=current,
        expires_at=current + timedelta(seconds=settings.AUTH_LOGIN_CHALLENGE_AGE_SECONDS),
        primary_credentials_verified_at=current,
        allowed_methods=list(allowed_methods),
        trust_browser=trust_browser,
        user_agent_summary=_request_user_agent(request),
        ip_address=_request_ip(request),
        created_request_id=_request_id(request),
    )
    return IssuedLoginChallenge(token=token, challenge=challenge)


def resolve_auth_session(token: str | None, *, request=None, now: datetime | None = None):
    if not isinstance(token, str) or not token or len(token) > MAX_COOKIE_TOKEN_LENGTH:
        return None
    current = now or timezone.now()
    digest = digest_opaque_token(token)
    session = (
        AuthSession.objects.select_related("user")
        .filter(
            token_digest=digest,
            revoked_at__isnull=True,
            expires_at__gt=current,
            user__is_active=True,
        )
        .first()
    )
    if session is None or not secrets.compare_digest(session.token_digest, digest):
        return None
    _touch_if_stale(session, model=AuthSession, request=request, now=current)
    return session


def resolve_trusted_session(token: str | None, *, request=None, now: datetime | None = None):
    if not isinstance(token, str) or not token or len(token) > MAX_COOKIE_TOKEN_LENGTH:
        return None
    current = now or timezone.now()
    digest = digest_opaque_token(token)
    trusted = (
        TrustedSession.objects.select_related("user")
        .filter(
            token_digest=digest,
            revoked_at__isnull=True,
            expires_at__gt=current,
            user__is_active=True,
        )
        .first()
    )
    if trusted is None or not secrets.compare_digest(trusted.token_digest, digest):
        return None
    _touch_if_stale(trusted, model=TrustedSession, request=request, now=current)
    return trusted


def resolve_login_challenge(token: str | None, *, now: datetime | None = None):
    if not isinstance(token, str) or not token or len(token) > MAX_COOKIE_TOKEN_LENGTH:
        return None
    current = now or timezone.now()
    digest = digest_opaque_token(token)
    challenge = (
        LoginChallenge.objects.select_related("user")
        .filter(
            challenge_digest=digest,
            consumed_at__isnull=True,
            expires_at__gt=current,
            user__is_active=True,
        )
        .first()
    )
    if challenge is None or not secrets.compare_digest(challenge.challenge_digest, digest):
        return None
    return challenge


def invalidate_login_challenges(*, user_id, now: datetime | None = None) -> int:
    """Invalidate every outstanding pre-authentication challenge for one account.

    ``LoginChallenge`` has one terminal timestamp, ``consumed_at``.  Administrative security
    changes use that existing terminal state rather than adding a second flag or deleting the
    historical challenge row.  The challenge is never presented as a successful login event.
    """

    current = now or timezone.now()
    count = 0
    challenges = LoginChallenge.objects.select_for_update().filter(
        user_id=user_id,
        consumed_at__isnull=True,
    )
    for challenge in challenges:
        challenge.consumed_at = current
        challenge.save(update_fields=["consumed_at"])
        count += 1
    return count


def record_session_created(
    *, user, session: AuthSession, context: AuditContext, method: str
) -> None:
    record_event(
        context=context,
        action=AUTH_SESSION_CREATED,
        outcome="SUCCESS",
        target_type="auth.session",
        target_id=session.pk,
        metadata={"method": method},
    )


def record_trusted_session_created(*, user, session: TrustedSession, context: AuditContext) -> None:
    record_event(
        context=context,
        action=AUTH_TRUSTED_SESSION_CREATED,
        outcome="SUCCESS",
        target_type="auth.trusted",
        target_id=session.pk,
        metadata={},
    )


def _revoke_auth_session_locked(
    session: AuthSession,
    *,
    context: AuditContext,
    now: datetime,
    reason: str,
) -> bool:
    if session.revoked_at is not None:
        return False
    session.revoked_at = now
    session.save(update_fields=["revoked_at"])
    record_event(
        context=context,
        action=AUTH_SESSION_REVOKED,
        outcome="SUCCESS",
        target_type="auth.session",
        target_id=session.pk,
        metadata={"reason": reason},
    )
    return True


def revoke_auth_session(
    *,
    session_id,
    context: AuditContext,
    user_id=None,
    reason: str = "revoked",
    now: datetime | None = None,
) -> bool:
    current = now or timezone.now()
    with transaction.atomic():
        session = AuthSession.objects.select_for_update().filter(pk=session_id).first()
        if session is None or (user_id is not None and session.user_id != user_id):
            return False
        return _revoke_auth_session_locked(session, context=context, now=current, reason=reason)


def revoke_all_auth_sessions(
    *,
    user_id,
    context: AuditContext,
    exclude_session_id=None,
    reason: str = "security_reset",
    now: datetime | None = None,
) -> int:
    current = now or timezone.now()
    count = 0
    with transaction.atomic():
        sessions = AuthSession.objects.select_for_update().filter(
            user_id=user_id,
            revoked_at__isnull=True,
        )
        if exclude_session_id is not None:
            sessions = sessions.exclude(pk=exclude_session_id)
        for session in sessions:
            count += _revoke_auth_session_locked(
                session,
                context=context,
                now=current,
                reason=reason,
            )
    return count


def revoke_other_auth_sessions(
    *,
    user_id,
    current_session_id,
    context: AuditContext,
    now: datetime | None = None,
) -> int:
    return revoke_all_auth_sessions(
        user_id=user_id,
        context=context,
        exclude_session_id=current_session_id,
        reason="revoke_others",
        now=now,
    )


def _revoke_trusted_session_locked(
    trusted: TrustedSession,
    *,
    context: AuditContext,
    now: datetime,
    reason: str,
) -> bool:
    if trusted.revoked_at is not None:
        return False
    trusted.revoked_at = now
    trusted.save(update_fields=["revoked_at"])
    record_event(
        context=context,
        action=AUTH_TRUSTED_SESSION_REVOKED,
        outcome="SUCCESS",
        target_type="auth.trusted",
        target_id=trusted.pk,
        metadata={"reason": reason},
    )
    return True


def revoke_trusted_session(
    *,
    session_id,
    context: AuditContext,
    user_id=None,
    reason: str = "revoked",
    now: datetime | None = None,
) -> bool:
    current = now or timezone.now()
    with transaction.atomic():
        trusted = TrustedSession.objects.select_for_update().filter(pk=session_id).first()
        if trusted is None or (user_id is not None and trusted.user_id != user_id):
            return False
        return _revoke_trusted_session_locked(
            trusted,
            context=context,
            now=current,
            reason=reason,
        )


def revoke_all_trusted_sessions(
    *,
    user_id,
    context: AuditContext,
    exclude_session_id=None,
    reason: str = "security_reset",
    now: datetime | None = None,
) -> int:
    current = now or timezone.now()
    count = 0
    with transaction.atomic():
        sessions = TrustedSession.objects.select_for_update().filter(
            user_id=user_id,
            revoked_at__isnull=True,
        )
        if exclude_session_id is not None:
            sessions = sessions.exclude(pk=exclude_session_id)
        for trusted in sessions:
            count += _revoke_trusted_session_locked(
                trusted,
                context=context,
                now=current,
                reason=reason,
            )
    return count


def has_recent_mfa(session: AuthSession, *, now: datetime | None = None) -> bool:
    if session.mfa_verified_at is None:
        return False
    current = now or timezone.now()
    return session.mfa_verified_at <= current and session.mfa_verified_at >= current - timedelta(
        seconds=settings.AUTH_RECENT_MFA_WINDOW_SECONDS
    )


def require_recent_mfa(session: AuthSession, *, now: datetime | None = None) -> None:
    if not has_recent_mfa(session, now=now):
        raise RecentMFARequired("recent MFA is required")


__all__ = [
    "IssuedLoginChallenge",
    "IssuedSession",
    "IssuedTrustedSession",
    "RecentMFARequired",
    "create_auth_session",
    "create_login_challenge",
    "create_trusted_session",
    "digest_opaque_token",
    "generate_opaque_token",
    "has_recent_mfa",
    "invalidate_login_challenges",
    "record_session_created",
    "record_trusted_session_created",
    "require_recent_mfa",
    "resolve_auth_session",
    "resolve_login_challenge",
    "resolve_trusted_session",
    "revoke_all_auth_sessions",
    "revoke_all_trusted_sessions",
    "revoke_auth_session",
    "revoke_other_auth_sessions",
    "revoke_trusted_session",
]
