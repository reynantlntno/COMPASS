"""Reusable authentication-state invalidation for account-security workflows."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from django.db import transaction
from django.utils import timezone

from compass.audit.context import AuditContext
from compass.authentication.email_otp import invalidate_email_otp_challenges
from compass.authentication.models import EmailOTPPurpose
from compass.authentication.sessions import (
    invalidate_login_challenges,
    revoke_all_auth_sessions,
    revoke_all_trusted_sessions,
)


@dataclass(frozen=True, slots=True)
class AuthStateInvalidation:
    """Non-sensitive counts from one account-security invalidation operation."""

    revoked_session_count: int
    revoked_trusted_session_count: int
    invalidated_login_challenge_count: int
    invalidated_email_challenge_count: int = 0


def invalidate_reusable_auth_state(
    *,
    user_id,
    context: AuditContext,
    reason: str,
    now: datetime | None = None,
    email_challenge_purposes: Iterable[str | EmailOTPPurpose] | None = None,
    email_challenge_email: str | None = None,
) -> AuthStateInvalidation:
    """Revoke reusable authentication state after a controlled account-security mutation.

    The caller normally invokes this inside the account mutation's outer transaction. The
    nested transaction here also keeps direct callers safe, while PostgreSQL row locks in the
    existing session services protect competing revocations. TOTP factors and recovery codes
    are deliberately untouched; MFA reset has a separate low-level operation. Password
    setup/reset can optionally invalidate only the requested email-OTP purposes in the same
    transaction.
    """

    current = now or timezone.now()
    with transaction.atomic():
        revoked_session_count = revoke_all_auth_sessions(
            user_id=user_id,
            context=context,
            reason=reason,
            now=current,
        )
        revoked_trusted_session_count = revoke_all_trusted_sessions(
            user_id=user_id,
            context=context,
            reason=reason,
            now=current,
        )
        invalidated_login_challenge_count = invalidate_login_challenges(
            user_id=user_id,
            now=current,
        )
        invalidated_email_challenge_count = 0
        if email_challenge_purposes is not None:
            invalidated_email_challenge_count = invalidate_email_otp_challenges(
                user_id=user_id,
                email=email_challenge_email,
                purposes=email_challenge_purposes,
                now=current,
            )
    return AuthStateInvalidation(
        revoked_session_count=revoked_session_count,
        revoked_trusted_session_count=revoked_trusted_session_count,
        invalidated_login_challenge_count=invalidated_login_challenge_count,
        invalidated_email_challenge_count=invalidated_email_challenge_count,
    )


def invalidate_auth_state_after_authority_change(
    *,
    user_id,
    context: AuditContext,
    reason: str,
    now: datetime | None = None,
    invalidate_email_security_challenges: bool = False,
    previous_email: str | None = None,
) -> AuthStateInvalidation:
    """Compatibility wrapper for administrative authority and identity mutations."""

    purposes = (
        (EmailOTPPurpose.SECURITY_CHALLENGE, EmailOTPPurpose.RECOVERY)
        if invalidate_email_security_challenges
        else None
    )
    return invalidate_reusable_auth_state(
        user_id=user_id,
        context=context,
        reason=reason,
        now=now,
        email_challenge_purposes=purposes,
        email_challenge_email=previous_email,
    )


__all__ = [
    "AuthStateInvalidation",
    "invalidate_auth_state_after_authority_change",
    "invalidate_reusable_auth_state",
]
