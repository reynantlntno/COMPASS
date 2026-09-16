"""Authentication-specific abuse controls built on the shared Redis limiter."""

from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings

from compass.common.rate_limit import (
    RateLimitPolicy,
    RateLimitUnavailable,
    RedisRateLimiter,
    client_ip,
)
from compass.integrations.turnstile import TurnstileConfigurationError, TurnstileVerifier


class AuthenticationRateLimited(RuntimeError):
    """Raised when an authentication operation exceeds one of its limits."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("authentication rate limit exceeded")
        self.retry_after_seconds = max(int(retry_after_seconds), 1)


class AuthenticationAbuseUnavailable(RuntimeError):
    """Raised when required Redis-backed abuse control cannot be evaluated."""


class TurnstileRejected(RuntimeError):
    """Raised by a security-sensitive flow when Turnstile is required but not valid."""


@dataclass(frozen=True, slots=True)
class AuthRateLimitSubject:
    kind: str
    value: str


_POLICIES: dict[str, tuple[tuple[str, RateLimitPolicy], ...]] = {
    "login": (
        ("ip", RateLimitPolicy("auth.login.ip", limit=30, window_seconds=15 * 60)),
        (
            "identifier",
            RateLimitPolicy("auth.login.identifier", limit=10, window_seconds=15 * 60),
        ),
        (
            "combination",
            RateLimitPolicy("auth.login.combination", limit=10, window_seconds=15 * 60),
        ),
    ),
    "totp": (
        ("user", RateLimitPolicy("auth.totp.user", limit=5, window_seconds=5 * 60)),
        ("combination", RateLimitPolicy("auth.totp.combination", limit=10, window_seconds=5 * 60)),
    ),
    "recovery": (
        ("user", RateLimitPolicy("auth.recovery.user", limit=5, window_seconds=15 * 60)),
        (
            "combination",
            RateLimitPolicy("auth.recovery.combination", limit=10, window_seconds=15 * 60),
        ),
    ),
    "email_otp_issue": (
        (
            "ip",
            RateLimitPolicy("auth.email_otp.issue.ip", limit=10, window_seconds=10 * 60),
        ),
        (
            "identifier",
            RateLimitPolicy("auth.email_otp.issue.identifier", limit=3, window_seconds=10 * 60),
        ),
        (
            "combination",
            RateLimitPolicy("auth.email_otp.issue.combination", limit=5, window_seconds=10 * 60),
        ),
    ),
    "email_otp_resend": (
        (
            "ip",
            RateLimitPolicy("auth.email_otp.resend.ip", limit=10, window_seconds=10 * 60),
        ),
        (
            "identifier",
            RateLimitPolicy("auth.email_otp.resend.identifier", limit=3, window_seconds=10 * 60),
        ),
        (
            "combination",
            RateLimitPolicy("auth.email_otp.resend.combination", limit=5, window_seconds=10 * 60),
        ),
    ),
    "email_otp_verify": (
        (
            "ip",
            RateLimitPolicy("auth.email_otp.verify.ip", limit=30, window_seconds=10 * 60),
        ),
        (
            "identifier",
            RateLimitPolicy("auth.email_otp.verify.identifier", limit=5, window_seconds=10 * 60),
        ),
        (
            "combination",
            RateLimitPolicy("auth.email_otp.verify.combination", limit=10, window_seconds=10 * 60),
        ),
    ),
}


def request_ip(request) -> str:
    return client_ip(request) if request is not None else "unknown"


def check_auth_rate_limit(
    operation: str,
    *,
    ip_address: str,
    identifier: str | None = None,
    user_id: object | None = None,
    limiter: RedisRateLimiter | None = None,
) -> None:
    """Consume the distinct controls for one authentication operation.

    The shared limiter hashes subjects before placing them in Redis. Authentication callers pass
    normalized identifiers only; no account email or user ID is used as a Redis key in plaintext.
    """

    try:
        policies = _POLICIES[operation]
    except KeyError as exc:
        raise ValueError(f"unknown authentication rate-limit operation: {operation}") from exc

    normalized_identifier = identifier.strip().lower() if isinstance(identifier, str) else None
    user_subject = str(user_id) if user_id is not None else None
    subjects = {
        "ip": f"ip:{ip_address or 'unknown'}",
        "identifier": f"identifier:{normalized_identifier}" if normalized_identifier else None,
        "user": f"user:{user_subject}" if user_subject else None,
        "combination": (
            f"combination:{ip_address or 'unknown'}:{normalized_identifier}"
            if normalized_identifier
            else (f"combination:{ip_address or 'unknown'}:{user_subject}" if user_subject else None)
        ),
    }
    active_limiter = limiter or RedisRateLimiter.from_settings()
    for subject_kind, policy in policies:
        subject = subjects.get(subject_kind)
        if not subject:
            continue
        try:
            result = active_limiter.consume_with_failure_policy(policy, subject)
        except RateLimitUnavailable as exc:
            raise AuthenticationAbuseUnavailable from exc
        if not result.allowed:
            raise AuthenticationRateLimited(result.retry_after_seconds)


_TURNSTILE_SETTINGS = {
    "login": "AUTH_TURNSTILE_LOGIN_REQUIRED",
    "email_otp": "AUTH_TURNSTILE_EMAIL_OTP_REQUIRED",
}


def verify_turnstile(request, token: str | None, *, flow: str) -> bool:
    """Verify Turnstile server-side only when the configured flow requires it."""

    try:
        setting_name = _TURNSTILE_SETTINGS[flow]
    except KeyError as exc:
        raise ValueError(f"unknown Turnstile flow: {flow}") from exc
    if not getattr(settings, setting_name):
        return True
    if not isinstance(token, str) or not token:
        return False
    if not settings.TURNSTILE_ENABLED:
        return False
    try:
        verifier = TurnstileVerifier.from_settings()
    except TurnstileConfigurationError:
        return False
    return verifier.verify(
        token,
        remote_ip=request_ip(request),
        expected_action=flow,
    ).success


__all__ = [
    "AuthRateLimitSubject",
    "AuthenticationAbuseUnavailable",
    "AuthenticationRateLimited",
    "TurnstileRejected",
    "check_auth_rate_limit",
    "request_ip",
    "verify_turnstile",
]
