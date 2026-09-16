"""Authentication flows composed from the explicit security services."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
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
    AUTH_LOGIN_FAILED,
    AUTH_LOGIN_MFA_REQUIRED,
    AUTH_LOGIN_SUCCESS,
    AUTH_LOGOUT,
    AUTH_MFA_TOTP_FAILED,
    AUTH_MFA_TOTP_VERIFIED,
)
from compass.authentication.mfa import (
    TOTPVerification,
    active_totp_factor,
    consume_recovery_code,
    has_active_totp_factor,
    mfa_required_for_user,
    verify_totp_for_login,
)
from compass.authentication.models import AuthSession, LoginChallenge
from compass.authentication.sessions import (
    IssuedLoginChallenge,
    IssuedSession,
    IssuedTrustedSession,
    create_auth_session,
    create_login_challenge,
    create_trusted_session,
    record_session_created,
    record_trusted_session_created,
    resolve_login_challenge,
    resolve_trusted_session,
    revoke_auth_session,
)

logger = logging.getLogger("compass.authentication")
User = get_user_model()
_DUMMY_PASSWORD_HASH = make_password(secrets.token_urlsafe(32))


class AuthenticationUnavailable(RuntimeError):
    """Raised when authentication cannot safely complete its required state transition."""


class InvalidLoginChallenge(RuntimeError):
    """Raised for missing, expired, consumed, or otherwise invalid pre-authentication state."""


LoginStatus = Literal[
    "failed",
    "mfa_required",
    "mfa_setup_required",
    "mfa_failed",
    "success",
]


@dataclass(frozen=True, slots=True)
class LoginResult:
    status: LoginStatus
    session: IssuedSession | None = None
    trusted_session: IssuedTrustedSession | None = None
    challenge: IssuedLoginChallenge | None = None
    mfa_methods: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return (
            f"LoginResult(status={self.status!r}, "
            f"session_id={self.session.session.pk if self.session else None!s})"
        )


def _context(*, request, user=None) -> AuditContext:
    if request is not None:
        return AuditContext.from_request(
            request,
            actor=user,
            actor_type=AuditActorType.USER if user is not None else AuditActorType.ANONYMOUS,
        )
    return AuditContext.user(user) if user is not None else AuditContext.anonymous()


def _best_effort_audit(*, request, user=None, action: str, outcome: str, metadata: dict) -> None:
    try:
        record_event(
            context=_context(request=request, user=user),
            action=action,
            outcome=outcome,
            target_type="accounts.user" if user is not None else None,
            target_id=user.pk if user is not None else None,
            metadata=metadata,
        )
    except Exception:
        # Authentication failures remain externally generic if the audit database is unavailable.
        # The event name is safe; no credential, submitted value, or request body is logged.
        logger.exception(
            "authentication failure could not be audited",
            extra={"event": "authentication_audit_failure", "action": action},
        )


def _password_matches(user, password: str) -> bool:
    try:
        if user is None:
            return check_password(password, _DUMMY_PASSWORD_HASH)
        return user.check_password(password)
    except (TypeError, ValueError):
        return False


def _authenticated_session(
    *,
    user,
    request,
    context: AuditContext,
    method: str,
    mfa_verified_at: datetime | None,
    now: datetime,
    trusted: bool = False,
) -> tuple[IssuedSession, IssuedTrustedSession | None]:
    try:
        with transaction.atomic():
            issued_session = create_auth_session(
                user,
                request=request,
                mfa_verified_at=mfa_verified_at,
                now=now,
            )
            record_event(
                context=context,
                action=AUTH_LOGIN_SUCCESS,
                outcome="SUCCESS",
                target_type="accounts.user",
                target_id=user.pk,
                metadata={"method": method},
            )
            record_session_created(
                user=user,
                session=issued_session.session,
                context=context,
                method=method,
            )
            issued_trusted = None
            if trusted:
                issued_trusted = create_trusted_session(user, request=request, now=now)
                record_trusted_session_created(
                    user=user,
                    session=issued_trusted.session,
                    context=context,
                )
    except Exception as exc:
        raise AuthenticationUnavailable from exc
    return issued_session, issued_trusted


def authenticate_login(
    *,
    request,
    email: str,
    password: str,
    trust_browser: bool = False,
    turnstile_token: str | None = None,
    limiter=None,
    now: datetime | None = None,
) -> LoginResult:
    """Verify primary credentials and either issue a session or create a short MFA challenge."""

    current = now or timezone.now()
    normalized_email = email.strip().lower() if isinstance(email, str) else ""
    try:
        check_auth_rate_limit(
            "login",
            ip_address=request_ip(request),
            identifier=normalized_email,
            limiter=limiter,
        )
    except AuthenticationRateLimited:
        _best_effort_audit(
            request=request,
            action=AUTH_LOGIN_FAILED,
            outcome="DENIED",
            metadata={"method": "rate_limit"},
        )
        raise
    except AuthenticationAbuseUnavailable as exc:
        raise AuthenticationUnavailable from exc

    if not verify_turnstile(request, turnstile_token, flow="login"):
        _best_effort_audit(
            request=request,
            action=AUTH_LOGIN_FAILED,
            outcome="DENIED",
            metadata={"method": "turnstile"},
        )
        return LoginResult(status="failed")

    user = User.objects.select_related("role").filter(email__iexact=normalized_email).first()
    password_valid = _password_matches(user, password)
    if user is None or not password_valid or not user.is_active:
        _best_effort_audit(
            request=request,
            user=user,
            action=AUTH_LOGIN_FAILED,
            outcome="DENIED",
            metadata={"method": "password"},
        )
        return LoginResult(status="failed")

    context = _context(request=request, user=user)
    if mfa_required_for_user(user):
        if not has_active_totp_factor(user.pk):
            _best_effort_audit(
                request=request,
                user=user,
                action=AUTH_LOGIN_MFA_REQUIRED,
                outcome="DENIED",
                metadata={"method": "totp_setup"},
            )
            return LoginResult(status="mfa_setup_required", mfa_methods=("totp",))

        trusted = resolve_trusted_session(
            request.COOKIES.get(settings.AUTH_TRUSTED_COOKIE_NAME),
            request=request,
            now=current,
        )
        if trusted is not None and trusted.user_id == user.pk:
            issued_session, issued_trusted = _authenticated_session(
                user=user,
                request=request,
                context=context,
                method="trusted_browser",
                mfa_verified_at=current,
                now=current,
            )
            return LoginResult(
                status="success",
                session=issued_session,
                trusted_session=issued_trusted,
            )

        try:
            with transaction.atomic():
                challenge = create_login_challenge(
                    user,
                    allowed_methods=["totp", "recovery"],
                    trust_browser=trust_browser,
                    request=request,
                    now=current,
                )
                record_event(
                    context=context,
                    action=AUTH_LOGIN_MFA_REQUIRED,
                    outcome="DENIED",
                    target_type="accounts.user",
                    target_id=user.pk,
                    metadata={"method": "totp"},
                )
        except Exception as exc:
            raise AuthenticationUnavailable from exc
        return LoginResult(
            status="mfa_required",
            challenge=challenge,
            mfa_methods=("totp", "recovery"),
        )

    issued_session, issued_trusted = _authenticated_session(
        user=user,
        request=request,
        context=context,
        method="password",
        mfa_verified_at=None,
        now=current,
    )
    return LoginResult(
        status="success",
        session=issued_session,
        trusted_session=issued_trusted,
    )


def complete_login_mfa(
    *,
    request,
    method: str,
    code: str,
    limiter=None,
    now: datetime | None = None,
) -> LoginResult:
    """Complete a short-lived MFA challenge without issuing a bearer token in JSON."""

    current = now or timezone.now()
    challenge_token = request.COOKIES.get(settings.AUTH_LOGIN_CHALLENGE_COOKIE_NAME)
    challenge = resolve_login_challenge(challenge_token, now=current)
    if challenge is None:
        raise InvalidLoginChallenge("login challenge is unavailable")
    normalized_method = method.strip().lower() if isinstance(method, str) else ""
    if normalized_method not in challenge.allowed_methods:
        raise InvalidLoginChallenge("login challenge is unavailable")
    operation = "totp" if normalized_method == "totp" else "recovery"
    try:
        check_auth_rate_limit(
            operation,
            ip_address=request_ip(request),
            user_id=challenge.user_id,
            limiter=limiter,
        )
    except AuthenticationRateLimited:
        raise
    except AuthenticationAbuseUnavailable as exc:
        raise AuthenticationUnavailable from exc

    try:
        with transaction.atomic():
            locked_challenge = (
                LoginChallenge.objects.select_for_update()
                .select_related("user")
                .filter(pk=challenge.pk)
                .first()
            )
            if (
                locked_challenge is None
                or locked_challenge.consumed_at is not None
                or locked_challenge.expires_at <= current
                or not locked_challenge.user.is_active
                or normalized_method not in locked_challenge.allowed_methods
            ):
                raise InvalidLoginChallenge("login challenge is unavailable")
            user = locked_challenge.user
            context = _context(request=request, user=user)
            verification: TOTPVerification | None = None
            if normalized_method == "totp":
                verification = verify_totp_for_login(user=user, code=code, now=current)
                if not verification.valid:
                    factor = active_totp_factor(user.pk)
                    record_event(
                        context=context,
                        action=AUTH_MFA_TOTP_FAILED,
                        outcome="DENIED",
                        target_type="auth.totpfactor" if factor is not None else None,
                        target_id=factor.pk if factor is not None else None,
                        metadata={"stage": "login"},
                    )
                    return LoginResult(
                        status="mfa_failed", mfa_methods=tuple(locked_challenge.allowed_methods)
                    )
                factor = active_totp_factor(user.pk)
                record_event(
                    context=context,
                    action=AUTH_MFA_TOTP_VERIFIED,
                    outcome="SUCCESS",
                    target_type="auth.totpfactor" if factor is not None else None,
                    target_id=factor.pk if factor is not None else None,
                    metadata={"stage": "login"},
                )
            else:
                matched = consume_recovery_code(user=user, code=code, context=context, now=current)
                if matched is None:
                    return LoginResult(
                        status="mfa_failed", mfa_methods=tuple(locked_challenge.allowed_methods)
                    )

            locked_challenge.consumed_at = current
            locked_challenge.save(update_fields=["consumed_at"])
            issued_session = create_auth_session(
                user,
                request=request,
                mfa_verified_at=current,
                now=current,
            )
            record_event(
                context=context,
                action=AUTH_LOGIN_SUCCESS,
                outcome="SUCCESS",
                target_type="accounts.user",
                target_id=user.pk,
                metadata={"method": normalized_method},
            )
            record_session_created(
                user=user,
                session=issued_session.session,
                context=context,
                method=normalized_method,
            )
            issued_trusted = None
            if locked_challenge.trust_browser:
                issued_trusted = create_trusted_session(user, request=request, now=current)
                record_trusted_session_created(
                    user=user,
                    session=issued_trusted.session,
                    context=context,
                )
    except InvalidLoginChallenge:
        raise
    except Exception as exc:
        raise AuthenticationUnavailable from exc
    return LoginResult(
        status="success",
        session=issued_session,
        trusted_session=issued_trusted,
    )


def logout_current_session(*, user, session: AuthSession, context: AuditContext) -> bool:
    try:
        with transaction.atomic():
            revoked = revoke_auth_session(
                session_id=session.pk,
                context=context,
                user_id=user.pk,
                reason="logout",
            )
            if revoked:
                record_event(
                    context=context,
                    action=AUTH_LOGOUT,
                    outcome="SUCCESS",
                    target_type="auth.session",
                    target_id=session.pk,
                    metadata={},
                )
            return revoked
    except Exception as exc:
        raise AuthenticationUnavailable from exc


__all__ = [
    "AuthenticationUnavailable",
    "InvalidLoginChallenge",
    "LoginResult",
    "authenticate_login",
    "complete_login_mfa",
    "logout_current_session",
]
