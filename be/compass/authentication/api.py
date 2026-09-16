"""Thin Django Ninja routes for cookie-based authentication."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from django.conf import settings
from django.http import HttpResponse
from django.middleware.csrf import get_token
from django.utils import timezone
from ninja import Router, Schema, Status
from ninja.security import APIKeyCookie
from ninja.utils import check_csrf

from compass.audit.context import AuditContext
from compass.authentication.abuse import (
    AuthenticationAbuseUnavailable,
    AuthenticationRateLimited,
)
from compass.authentication.email_otp import EmailOTPInvalid, EmailOTPSecurityUnavailable
from compass.authentication.mfa import (
    TOTPAlreadyConfigured,
    TOTPEnrollmentMissing,
    TOTPNotConfigured,
    confirm_totp_enrollment,
    disable_totp,
    regenerate_recovery_codes,
    start_totp_enrollment,
    verify_totp_for_session,
)
from compass.authentication.models import AuthSession, TrustedSession
from compass.authentication.password_access import (
    PASSWORD_ACCESS_MESSAGE,
    PASSWORD_CHALLENGE_INVALID_MESSAGE,
    InvalidPasswordAccessRequest,
    PasswordChallengeInvalid,
    PasswordPolicyRejected,
    confirm_password_access,
    request_password_access,
)
from compass.authentication.services import (
    AuthenticationUnavailable,
    InvalidLoginChallenge,
    LoginResult,
    authenticate_login,
    complete_login_mfa,
    logout_current_session,
)
from compass.authentication.sessions import (
    has_recent_mfa,
    resolve_trusted_session,
    revoke_all_trusted_sessions,
    revoke_auth_session,
    revoke_other_auth_sessions,
    revoke_trusted_session,
)
from compass.common.api import response_with_errors
from compass.common.errors import APIError
from compass.common.rate_limit import client_ip

router = Router(tags=["auth"])


class UserSummary(Schema):
    id: UUID
    email: str
    first_name: str
    last_name: str
    role: str


class CSRFResponse(Schema):
    csrf_token: str


class LoginRequest(Schema):
    email: str
    password: str
    trust_browser: bool = False
    turnstile_token: str | None = None


class LoginResponse(Schema):
    authenticated: bool
    mfa_required: bool
    mfa_methods: list[str]
    session_id: UUID | None = None
    challenge_expires_at: datetime | None = None
    user: UserSummary | None = None


class MFARequest(Schema):
    code: str


class LoginMFARequest(Schema):
    method: str
    code: str


class PasswordAccessRequest(Schema):
    email: str
    turnstile_token: str | None = None


class PasswordAccessRequestResponse(Schema):
    challenge_id: UUID
    expires_at: datetime
    message: str


class PasswordAccessConfirmRequest(Schema):
    challenge_id: UUID
    code: str
    new_password: str


class PasswordAccessConfirmResponse(Schema):
    password_set: bool


class SessionSummary(Schema):
    id: UUID
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    mfa_verified_at: datetime | None
    mfa_recent: bool
    user_agent_summary: str | None
    initial_ip_address: str | None
    last_ip_address: str | None
    is_current: bool


class CurrentSessionResponse(Schema):
    authenticated: bool
    user: UserSummary
    session: SessionSummary


class SessionListResponse(Schema):
    sessions: list[SessionSummary]


class RevokeResponse(Schema):
    revoked: bool


class RevokeManyResponse(Schema):
    revoked_count: int


class TOTPSetupResponse(Schema):
    factor_id: UUID
    provisioning_uri: str


class TOTPConfirmationResponse(Schema):
    enabled: bool
    recovery_codes: list[str]


class MFAStatusResponse(Schema):
    enabled: bool
    recent: bool


class TrustedSessionSummary(Schema):
    id: UUID
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    user_agent_summary: str | None
    created_ip_address: str | None
    last_ip_address: str | None
    is_current: bool


class TrustedSessionListResponse(Schema):
    sessions: list[TrustedSessionSummary]


class OpaqueSessionAuth(APIKeyCookie):
    """Resolve the COMPASS opaque cookie and enforce CSRF before authentication."""

    openapi_description = (
        "HttpOnly opaque COMPASS session cookie. The browser sends it automatically; it is not a "
        "Bearer token. State-changing requests also require Django CSRF protection."
    )
    param_name = settings.AUTH_SESSION_COOKIE_NAME

    def __init__(self) -> None:
        # APIKeyCookie's built-in CSRF behavior raises Ninja's generic HttpError. We perform the
        # same proven Django check here so COMPASS can render its central JSON error contract.
        super().__init__(csrf=False)

    def _get_key(self, request):
        if check_csrf(request):
            raise APIError(403, "csrf_failed", "CSRF validation failed.")
        return request.COOKIES.get(self.param_name)

    def authenticate(self, request, key):
        from compass.authentication.sessions import resolve_auth_session

        session = resolve_auth_session(key, request=request)
        if session is None:
            return None
        request.auth_session = session
        request.auth_user = session.user
        return session.user


session_auth = OpaqueSessionAuth()


def _require_csrf(request) -> None:
    if check_csrf(request):
        raise APIError(403, "csrf_failed", "CSRF validation failed.")


def _user_summary(user) -> dict[str, object]:
    return {
        "id": user.pk,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": user.role.code,
    }


def _session_summary(session: AuthSession, *, current_session_id=None) -> dict[str, object]:
    return {
        "id": session.pk,
        "created_at": session.created_at,
        "last_used_at": session.last_used_at,
        "expires_at": session.expires_at,
        "revoked_at": session.revoked_at,
        "mfa_verified_at": session.mfa_verified_at,
        "mfa_recent": has_recent_mfa(session),
        "user_agent_summary": session.user_agent_summary,
        "initial_ip_address": session.initial_ip_address,
        "last_ip_address": session.last_ip_address,
        "is_current": session.pk == current_session_id,
    }


def _trusted_summary(session: TrustedSession, *, current_session_id=None) -> dict[str, object]:
    return {
        "id": session.pk,
        "created_at": session.created_at,
        "last_used_at": session.last_used_at,
        "expires_at": session.expires_at,
        "revoked_at": session.revoked_at,
        "user_agent_summary": session.user_agent_summary,
        "created_ip_address": session.created_ip_address,
        "last_ip_address": session.last_ip_address,
        "is_current": session.pk == current_session_id,
    }


def _set_credential_cookie(
    response: HttpResponse,
    *,
    name: str,
    value: str,
    max_age: int,
    path: str,
    httponly: bool,
) -> None:
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        path=path,
        domain=settings.AUTH_SESSION_COOKIE_DOMAIN,
        secure=settings.AUTH_COOKIE_SECURE,
        httponly=httponly,
        samesite=settings.AUTH_COOKIE_SAMESITE,
    )


def _delete_cookie(response: HttpResponse, *, name: str, path: str) -> None:
    response.delete_cookie(
        name,
        path=path,
        domain=settings.AUTH_SESSION_COOKIE_DOMAIN,
        samesite=settings.AUTH_COOKIE_SAMESITE,
    )


def _apply_login_cookies(response: HttpResponse, result: LoginResult) -> None:
    if result.status == "success" and result.session is not None:
        _set_credential_cookie(
            response,
            name=settings.AUTH_SESSION_COOKIE_NAME,
            value=result.session.token,
            max_age=settings.AUTH_SESSION_AGE_SECONDS,
            path=settings.AUTH_SESSION_COOKIE_PATH,
            httponly=True,
        )
        if result.trusted_session is not None:
            _set_credential_cookie(
                response,
                name=settings.AUTH_TRUSTED_COOKIE_NAME,
                value=result.trusted_session.token,
                max_age=settings.AUTH_TRUSTED_SESSION_AGE_SECONDS,
                path=settings.AUTH_TRUSTED_COOKIE_PATH,
                httponly=True,
            )
        _delete_cookie(
            response,
            name=settings.AUTH_LOGIN_CHALLENGE_COOKIE_NAME,
            path=settings.AUTH_LOGIN_CHALLENGE_COOKIE_PATH,
        )
        return
    if result.status == "mfa_required" and result.challenge is not None:
        _set_credential_cookie(
            response,
            name=settings.AUTH_LOGIN_CHALLENGE_COOKIE_NAME,
            value=result.challenge.token,
            max_age=settings.AUTH_LOGIN_CHALLENGE_AGE_SECONDS,
            path=settings.AUTH_LOGIN_CHALLENGE_COOKIE_PATH,
            httponly=True,
        )
        _delete_cookie(
            response,
            name=settings.AUTH_SESSION_COOKIE_NAME,
            path=settings.AUTH_SESSION_COOKIE_PATH,
        )
        return
    _delete_cookie(
        response,
        name=settings.AUTH_LOGIN_CHALLENGE_COOKIE_NAME,
        path=settings.AUTH_LOGIN_CHALLENGE_COOKIE_PATH,
    )


def _login_response(result: LoginResult) -> dict[str, object]:
    if result.status == "success" and result.session is not None:
        return {
            "authenticated": True,
            "mfa_required": False,
            "mfa_methods": [],
            "session_id": result.session.session.pk,
            "user": _user_summary(result.session.session.user),
        }
    return {
        "authenticated": False,
        "mfa_required": result.status in {"mfa_required", "mfa_setup_required"},
        "mfa_methods": list(result.mfa_methods),
        "challenge_expires_at": (
            result.challenge.challenge.expires_at if result.challenge is not None else None
        ),
    }


def _raise_rate_limited(exc: AuthenticationRateLimited) -> None:
    raise APIError(
        429,
        "rate_limited",
        "Too many authentication attempts. Please try again later.",
        headers={"Retry-After": str(exc.retry_after_seconds)},
    ) from exc


def _raise_security_unavailable(exc: Exception) -> None:
    raise APIError(
        503,
        "security_unavailable",
        "Authentication is temporarily unavailable.",
    ) from exc


def _raise_invalid_mfa(exc: Exception) -> None:
    raise APIError(400, "mfa_failed", "The MFA response could not be verified.") from exc


def _raise_password_challenge_invalid(exc: Exception) -> None:
    raise APIError(400, "password_challenge_invalid", PASSWORD_CHALLENGE_INVALID_MESSAGE) from exc


def _raise_password_policy(exc: PasswordPolicyRejected) -> None:
    raise APIError(
        422,
        "password_policy_failed",
        str(exc),
        details=[issue.as_dict() for issue in exc.issues],
    ) from exc


@router.get(
    "/csrf",
    response=CSRFResponse,
    operation_id="authGetCsrf",
    summary="Obtain the CSRF token cookie",
    description=(
        "Return the readable Django CSRF token and issue the CSRF cookie. "
        "The HttpOnly authentication cookie is not returned."
    ),
)
def csrf_token(request):
    """Return a masked Django CSRF token and cause the CSRF cookie to be issued."""

    return {"csrf_token": get_token(request)}


@router.post(
    "/login",
    response=response_with_errors(LoginResponse, 401, 403, 422, 429, 503),
    operation_id="authLogin",
    summary="Authenticate with email and password",
)
def login(request, payload: LoginRequest, response: HttpResponse):
    _require_csrf(request)
    try:
        result = authenticate_login(
            request=request,
            email=payload.email,
            password=payload.password,
            trust_browser=payload.trust_browser,
            turnstile_token=payload.turnstile_token,
        )
    except AuthenticationRateLimited as exc:
        _raise_rate_limited(exc)
    except AuthenticationUnavailable as exc:
        _raise_security_unavailable(exc)
    _apply_login_cookies(response, result)
    if result.status == "failed":
        raise APIError(401, "authentication_failed", "Invalid email or password.")
    if result.status == "mfa_setup_required":
        raise APIError(403, "mfa_setup_required", "Additional account security setup is required.")
    return _login_response(result)


@router.post(
    "/password/request",
    response=response_with_errors(
        PasswordAccessRequestResponse,
        400,
        403,
        422,
        429,
        503,
        success_status=202,
    ),
    operation_id="authRequestPasswordAccess",
    summary="Request password setup or recovery",
    description=(
        "Request a one-time email security code for initial password setup or password recovery. "
        "The response is intentionally the same for eligible, disabled, and unknown accounts."
    ),
)
def password_request(request, payload: PasswordAccessRequest):
    _require_csrf(request)
    try:
        result = request_password_access(
            email=payload.email,
            request=request,
            turnstile_token=payload.turnstile_token,
        )
    except AuthenticationRateLimited as exc:
        _raise_rate_limited(exc)
    except AuthenticationAbuseUnavailable as exc:
        _raise_security_unavailable(exc)
    except InvalidPasswordAccessRequest as exc:
        raise APIError(422, "invalid_password_request", str(exc)) from exc
    except EmailOTPSecurityUnavailable as exc:
        _raise_security_unavailable(exc)
    except EmailOTPInvalid as exc:
        raise APIError(
            403,
            "security_verification_failed",
            "The security verification could not be completed.",
        ) from exc
    except Exception as exc:
        _raise_security_unavailable(exc)
    return Status(
        202,
        {
            "challenge_id": result.challenge.pk,
            "expires_at": result.challenge.expires_at,
            "message": PASSWORD_ACCESS_MESSAGE,
        },
    )


@router.post(
    "/password/confirm",
    response=response_with_errors(PasswordAccessConfirmResponse, 400, 403, 422, 429, 503),
    operation_id="authConfirmPasswordAccess",
    summary="Complete password setup or recovery",
    description=(
        "Atomically verify the email security code and establish or replace the password. "
        "Successful completion does not create an authentication session."
    ),
)
def password_confirm(request, payload: PasswordAccessConfirmRequest):
    _require_csrf(request)
    try:
        result = confirm_password_access(
            challenge_id=payload.challenge_id,
            code=payload.code,
            new_password=payload.new_password,
            request=request,
        )
    except AuthenticationRateLimited as exc:
        _raise_rate_limited(exc)
    except AuthenticationAbuseUnavailable as exc:
        _raise_security_unavailable(exc)
    except PasswordChallengeInvalid as exc:
        _raise_password_challenge_invalid(exc)
    except PasswordPolicyRejected as exc:
        _raise_password_policy(exc)
    except Exception as exc:
        _raise_security_unavailable(exc)
    return {"password_set": result.password_set}


@router.post(
    "/mfa/verify",
    response=response_with_errors(LoginResponse, 400, 403, 422, 429, 503),
    operation_id="authVerifyLoginMfa",
    summary="Complete a login MFA challenge",
)
def verify_login_mfa(request, payload: LoginMFARequest, response: HttpResponse):
    _require_csrf(request)
    try:
        result = complete_login_mfa(
            request=request,
            method=payload.method,
            code=payload.code,
        )
    except AuthenticationRateLimited as exc:
        _raise_rate_limited(exc)
    except (InvalidLoginChallenge, AuthenticationUnavailable) as exc:
        if isinstance(exc, AuthenticationUnavailable):
            _raise_security_unavailable(exc)
        raise APIError(400, "mfa_failed", "The MFA response could not be verified.") from exc
    _apply_login_cookies(response, result)
    if result.status == "mfa_failed":
        _raise_invalid_mfa(InvalidLoginChallenge("invalid MFA response"))
    return _login_response(result)


@router.post(
    "/logout",
    response=response_with_errors(RevokeResponse, 401, 403, 503),
    auth=session_auth,
    operation_id="authLogout",
    summary="Log out the current session",
)
def logout(request, response: HttpResponse):
    user = request.auth_user
    session = request.auth_session
    try:
        revoked = logout_current_session(
            user=user,
            session=session,
            context=AuditContext.from_request(request, actor=user),
        )
    except AuthenticationUnavailable as exc:
        _raise_security_unavailable(exc)
    _delete_cookie(
        response, name=settings.AUTH_SESSION_COOKIE_NAME, path=settings.AUTH_SESSION_COOKIE_PATH
    )
    return {"revoked": revoked}


@router.get(
    "/session",
    response=response_with_errors(CurrentSessionResponse, 401),
    auth=session_auth,
    operation_id="authGetSession",
    summary="Inspect the current session",
)
def current_session(request):
    session = request.auth_session
    user = request.auth_user
    return {
        "authenticated": True,
        "user": _user_summary(user),
        "session": _session_summary(session, current_session_id=session.pk),
    }


@router.get(
    "/sessions",
    response=response_with_errors(SessionListResponse, 401),
    auth=session_auth,
    operation_id="authListSessions",
    summary="List active sessions",
)
def sessions(request):
    user = request.auth_user
    current = timezone.now()
    records = AuthSession.objects.filter(
        user_id=user.pk,
        revoked_at__isnull=True,
        expires_at__gt=current,
    )[: settings.AUTH_MAX_SESSION_LIST_SIZE]
    return {
        "sessions": [
            _session_summary(record, current_session_id=request.auth_session.pk)
            for record in records
        ]
    }


@router.post(
    "/sessions/revoke-others",
    response=response_with_errors(RevokeManyResponse, 401, 403, 503),
    auth=session_auth,
    operation_id="authRevokeOtherSessions",
    summary="Revoke all other sessions",
)
def revoke_other_sessions(request):
    user = request.auth_user
    try:
        count = revoke_other_auth_sessions(
            user_id=user.pk,
            current_session_id=request.auth_session.pk,
            context=AuditContext.from_request(request, actor=user),
        )
    except Exception as exc:
        _raise_security_unavailable(exc)
    return {"revoked_count": count}


@router.delete(
    "/sessions/{session_id}",
    response=response_with_errors(RevokeResponse, 401, 403, 404, 422, 503),
    auth=session_auth,
    operation_id="authRevokeSession",
    summary="Revoke one session",
)
def revoke_session(request, session_id: UUID, response: HttpResponse):
    user = request.auth_user
    try:
        revoked = revoke_auth_session(
            session_id=session_id,
            context=AuditContext.from_request(request, actor=user),
            user_id=user.pk,
            reason="user_revoked",
        )
    except Exception as exc:
        _raise_security_unavailable(exc)
    if not revoked:
        raise APIError(404, "not_found", "The requested session was not found.")
    if session_id == request.auth_session.pk:
        _delete_cookie(
            response, name=settings.AUTH_SESSION_COOKIE_NAME, path=settings.AUTH_SESSION_COOKIE_PATH
        )
    return {"revoked": True}


@router.post(
    "/mfa/totp/setup",
    response=response_with_errors(TOTPSetupResponse, 401, 403, 409, 503),
    auth=session_auth,
    operation_id="authStartTotpSetup",
    summary="Start TOTP enrollment",
)
def totp_setup(request):
    user = request.auth_user
    try:
        result = start_totp_enrollment(
            user=user,
            context=AuditContext.from_request(request, actor=user),
        )
    except TOTPAlreadyConfigured as exc:
        raise APIError(409, "mfa_already_enabled", "TOTP is already enabled.") from exc
    except Exception as exc:
        _raise_security_unavailable(exc)
    return {"factor_id": result.factor_id, "provisioning_uri": result.provisioning_uri}


@router.post(
    "/mfa/totp/confirm",
    response=response_with_errors(TOTPConfirmationResponse, 400, 401, 403, 422, 429, 503),
    auth=session_auth,
    operation_id="authConfirmTotpSetup",
    summary="Confirm TOTP enrollment",
)
def totp_confirm(request, payload: MFARequest):
    user = request.auth_user
    try:
        from compass.authentication.abuse import check_auth_rate_limit

        check_auth_rate_limit("totp", ip_address=client_ip(request), user_id=user.pk)
        result = confirm_totp_enrollment(
            user=user,
            code=payload.code,
            context=AuditContext.from_request(request, actor=user),
        )
    except AuthenticationRateLimited as exc:
        _raise_rate_limited(exc)
    except AuthenticationAbuseUnavailable as exc:
        _raise_security_unavailable(exc)
    except TOTPEnrollmentMissing as exc:
        raise APIError(400, "mfa_failed", "The MFA response could not be verified.") from exc
    except Exception as exc:
        _raise_security_unavailable(exc)
    if result is None:
        _raise_invalid_mfa(TOTPEnrollmentMissing("invalid TOTP code"))
    return {"enabled": True, "recovery_codes": list(result.recovery_codes)}


@router.post(
    "/mfa/totp/verify",
    response=response_with_errors(MFAStatusResponse, 400, 401, 403, 422, 429, 503),
    auth=session_auth,
    operation_id="authVerifyTotp",
    summary="Verify TOTP for step-up authentication",
)
def totp_verify(request, payload: MFARequest):
    user = request.auth_user
    try:
        from compass.authentication.abuse import check_auth_rate_limit

        check_auth_rate_limit("totp", ip_address=client_ip(request), user_id=user.pk)
        verification = verify_totp_for_session(
            user=user,
            session=request.auth_session,
            code=payload.code,
            context=AuditContext.from_request(request, actor=user),
        )
    except AuthenticationRateLimited as exc:
        _raise_rate_limited(exc)
    except AuthenticationAbuseUnavailable as exc:
        _raise_security_unavailable(exc)
    except Exception as exc:
        _raise_security_unavailable(exc)
    if not verification.valid:
        _raise_invalid_mfa(InvalidLoginChallenge("invalid TOTP code"))
    return {"enabled": True, "recent": True}


@router.post(
    "/mfa/totp/disable",
    response=response_with_errors(MFAStatusResponse, 400, 401, 403, 503),
    auth=session_auth,
    operation_id="authDisableTotp",
    summary="Disable the current TOTP factor",
)
def totp_disable(request):
    user = request.auth_user
    try:
        disable_totp(
            user=user,
            session=request.auth_session,
            context=AuditContext.from_request(request, actor=user),
        )
    except Exception as exc:
        from compass.authentication.sessions import RecentMFARequired

        if isinstance(exc, RecentMFARequired):
            raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
        if isinstance(exc, TOTPNotConfigured):
            raise APIError(400, "mfa_not_configured", "TOTP is not enabled.") from exc
        _raise_security_unavailable(exc)
    return {"enabled": False, "recent": has_recent_mfa(request.auth_session)}


@router.post(
    "/mfa/recovery-codes/regenerate",
    response=response_with_errors(TOTPConfirmationResponse, 400, 401, 403, 503),
    auth=session_auth,
    operation_id="authRegenerateRecoveryCodes",
    summary="Regenerate MFA recovery codes",
)
def recovery_codes_regenerate(request):
    user = request.auth_user
    try:
        codes = regenerate_recovery_codes(
            user=user,
            session=request.auth_session,
            context=AuditContext.from_request(request, actor=user),
        )
    except Exception as exc:
        from compass.authentication.sessions import RecentMFARequired

        if isinstance(exc, RecentMFARequired):
            raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
        if isinstance(exc, TOTPNotConfigured):
            raise APIError(400, "mfa_not_configured", "TOTP is not enabled.") from exc
        _raise_security_unavailable(exc)
    return {"enabled": True, "recovery_codes": list(codes)}


@router.get(
    "/trusted-sessions",
    response=response_with_errors(TrustedSessionListResponse, 401),
    auth=session_auth,
    operation_id="authListTrustedSessions",
    summary="List trusted browser sessions",
)
def trusted_sessions(request):
    user = request.auth_user
    current_trusted = resolve_trusted_session(
        request.COOKIES.get(settings.AUTH_TRUSTED_COOKIE_NAME), request=request
    )
    records = TrustedSession.objects.filter(
        user_id=user.pk,
        revoked_at__isnull=True,
        expires_at__gt=timezone.now(),
    )[: settings.AUTH_MAX_SESSION_LIST_SIZE]
    return {
        "sessions": [
            _trusted_summary(
                record,
                current_session_id=current_trusted.pk if current_trusted is not None else None,
            )
            for record in records
        ]
    }


@router.post(
    "/trusted-sessions/revoke-others",
    response=response_with_errors(RevokeManyResponse, 401, 403, 503),
    auth=session_auth,
    operation_id="authRevokeOtherTrustedSessions",
    summary="Revoke other trusted browser sessions",
)
def revoke_other_trusted_sessions(request):
    user = request.auth_user
    current_trusted = resolve_trusted_session(
        request.COOKIES.get(settings.AUTH_TRUSTED_COOKIE_NAME), request=request
    )
    try:
        count = revoke_all_trusted_sessions(
            user_id=user.pk,
            exclude_session_id=current_trusted.pk if current_trusted is not None else None,
            context=AuditContext.from_request(request, actor=user),
            reason="revoke_others",
        )
    except Exception as exc:
        _raise_security_unavailable(exc)
    return {"revoked_count": count}


@router.delete(
    "/trusted-sessions/{session_id}",
    response=response_with_errors(RevokeResponse, 401, 403, 404, 422, 503),
    auth=session_auth,
    operation_id="authRevokeTrustedSession",
    summary="Revoke one trusted browser session",
)
def revoke_trusted(request, session_id: UUID, response: HttpResponse):
    user = request.auth_user
    current_trusted = resolve_trusted_session(
        request.COOKIES.get(settings.AUTH_TRUSTED_COOKIE_NAME), request=request
    )
    try:
        revoked = revoke_trusted_session(
            session_id=session_id,
            context=AuditContext.from_request(request, actor=user),
            user_id=user.pk,
            reason="user_revoked",
        )
    except Exception as exc:
        _raise_security_unavailable(exc)
    if not revoked:
        raise APIError(404, "not_found", "The requested trusted session was not found.")
    if current_trusted is not None and current_trusted.pk == session_id:
        _delete_cookie(
            response, name=settings.AUTH_TRUSTED_COOKIE_NAME, path=settings.AUTH_TRUSTED_COOKIE_PATH
        )
    return {"revoked": True}


__all__ = ["router", "session_auth"]
