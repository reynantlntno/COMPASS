"""Reusable account-security state invalidation for administrative workflows."""

from __future__ import annotations

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


def invalidate_auth_state_after_authority_change(
    *,
    user_id,
    context: AuditContext,
    reason: str,
    now: datetime | None = None,
    invalidate_email_security_challenges: bool = False,
    previous_email: str | None = None,
) -> AuthStateInvalidation:
    """Revoke reusable authentication state after a controlled account mutation.

    The caller normally invokes this inside the account mutation's outer transaction. The
    nested transaction here also keeps direct callers safe, while PostgreSQL row locks in the
    existing session services protect competing revocations. TOTP factors and recovery codes
    are deliberately untouched; MFA reset has a separate low-level operation.
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
        if invalidate_email_security_challenges:
            invalidated_email_challenge_count = invalidate_email_otp_challenges(
                user_id=user_id,
                email=previous_email,
                purposes=(EmailOTPPurpose.SECURITY_CHALLENGE, EmailOTPPurpose.RECOVERY),
                now=current,
            )
    return AuthStateInvalidation(
        revoked_session_count=revoked_session_count,
        revoked_trusted_session_count=revoked_trusted_session_count,
        invalidated_login_challenge_count=invalidated_login_challenge_count,
        invalidated_email_challenge_count=invalidated_email_challenge_count,
    )


__all__ = [
    "AuthStateInvalidation",
    "invalidate_auth_state_after_authority_change",
]
