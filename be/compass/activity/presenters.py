"""Explicit, safe presenters for user-facing activity projections.

The registries in this module are deliberately closed-world: an AuditEvent action is invisible
to users until it is explicitly registered here with a safe target and outcome policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from compass.audit.actions import (
    ACCOUNT_CREATED,
    ACCOUNT_DESIGNATION_ASSIGNED,
    ACCOUNT_DESIGNATION_REMOVED,
    ACCOUNT_DISABLED,
    ACCOUNT_ENABLED,
    ACCOUNT_MFA_RESET,
    ACCOUNT_ROLE_CHANGED,
    ACCOUNT_UPDATED,
)
from compass.audit.models import AuditEvent, AuditOutcome
from compass.authentication.actions import (
    AUTH_LOGIN_FAILED,
    AUTH_LOGIN_SUCCESS,
    AUTH_LOGOUT,
    AUTH_MFA_RECOVERY_CODE_USED,
    AUTH_MFA_RECOVERY_CODES_REGENERATED,
    AUTH_MFA_TOTP_DISABLED,
    AUTH_MFA_TOTP_ENROLLED,
    AUTH_PASSWORD_INITIAL_SET,
    AUTH_PASSWORD_RESET,
    AUTH_SESSION_CREATED,
    AUTH_SESSION_REVOKED,
    AUTH_TRUSTED_SESSION_CREATED,
    AUTH_TRUSTED_SESSION_REVOKED,
)

ACCOUNT_TARGET = "accounts.user"
AUTH_SESSION_TARGET = "auth.session"
AUTH_TRUSTED_SESSION_TARGET = "auth.trusted"
AUTH_TOTP_FACTOR_TARGET = "auth.totpfactor"
AUTH_RECOVERY_CODE_TARGET = "auth.recoverycode"

ActorScope = Literal["self_actor", "system_target", "target_user"]

_SUCCESS = frozenset({AuditOutcome.SUCCESS.value})
_DENIED = frozenset({AuditOutcome.DENIED.value})


@dataclass(frozen=True, slots=True)
class ActivityItem:
    """The intentionally small public representation of one activity item."""

    id: UUID
    type: str
    title: str
    description: str
    occurred_at: datetime

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "occurred_at": self.occurred_at,
        }


@dataclass(frozen=True, slots=True)
class ActivityPresenter:
    """Static presentation and selection policy for one canonical audit action."""

    item_type: str
    title: str
    description: str
    target_type: str
    actor_scope: ActorScope
    visible_outcomes: frozenset[str]

    def present(self, event: AuditEvent) -> ActivityItem:
        """Render only safe, stable copy; no audit metadata is consulted or returned."""

        return ActivityItem(
            id=event.id,
            type=self.item_type,
            title=self.title,
            description=self.description,
            occurred_at=event.occurred_at,
        )


def _presenter(
    *,
    item_type: str,
    title: str,
    description: str,
    target_type: str,
    actor_scope: ActorScope = "self_actor",
    visible_outcomes: frozenset[str] = _SUCCESS,
) -> ActivityPresenter:
    return ActivityPresenter(
        item_type=item_type,
        title=title,
        description=description,
        target_type=target_type,
        actor_scope=actor_scope,
        visible_outcomes=visible_outcomes,
    )


# My Activity contains meaningful account activity. Low-level MFA verification, setup attempts,
# email OTP operations, and failed security checks are intentionally not part of this broader feed.
MY_ACTIVITY_PRESENTERS: dict[str, ActivityPresenter] = {
    ACCOUNT_CREATED: _presenter(
        item_type="account.created",
        title="Your COMPASS account was created",
        description="Your account is ready to use.",
        target_type=ACCOUNT_TARGET,
        actor_scope="target_user",
    ),
    ACCOUNT_UPDATED: _presenter(
        item_type="account.updated",
        title="Your account information was updated",
        description="Your COMPASS account information was updated.",
        target_type=ACCOUNT_TARGET,
        actor_scope="target_user",
    ),
    ACCOUNT_DISABLED: _presenter(
        item_type="account.disabled",
        title="Your account was disabled",
        description="Your COMPASS account was disabled by an administrator.",
        target_type=ACCOUNT_TARGET,
        actor_scope="target_user",
    ),
    ACCOUNT_ENABLED: _presenter(
        item_type="account.enabled",
        title="Your account was re-enabled",
        description="Your COMPASS account was re-enabled by an administrator.",
        target_type=ACCOUNT_TARGET,
        actor_scope="target_user",
    ),
    ACCOUNT_ROLE_CHANGED: _presenter(
        item_type="account.role.changed",
        title="Your account role was updated",
        description="Your COMPASS account role was updated.",
        target_type=ACCOUNT_TARGET,
        actor_scope="target_user",
    ),
    ACCOUNT_DESIGNATION_ASSIGNED: _presenter(
        item_type="account.designation.assigned",
        title="A designation was assigned to your account",
        description="A designation was assigned to your COMPASS account.",
        target_type=ACCOUNT_TARGET,
        actor_scope="target_user",
    ),
    ACCOUNT_DESIGNATION_REMOVED: _presenter(
        item_type="account.designation.removed",
        title="A designation was removed from your account",
        description="A designation was removed from your COMPASS account.",
        target_type=ACCOUNT_TARGET,
        actor_scope="target_user",
    ),
    ACCOUNT_MFA_RESET: _presenter(
        item_type="account.mfa.reset",
        title="Your authenticator setup was reset",
        description="Your COMPASS authenticator setup was reset by an administrator.",
        target_type=ACCOUNT_TARGET,
        actor_scope="target_user",
    ),
    AUTH_LOGIN_SUCCESS: _presenter(
        item_type="auth.login",
        title="Signed in to COMPASS",
        description="You signed in to your account.",
        target_type=ACCOUNT_TARGET,
    ),
    AUTH_LOGOUT: _presenter(
        item_type="auth.logout",
        title="Signed out of COMPASS",
        description="You signed out of your account.",
        target_type=AUTH_SESSION_TARGET,
    ),
    AUTH_SESSION_REVOKED: _presenter(
        item_type="auth.session.revoked",
        title="Session signed out",
        description="A COMPASS session was signed out.",
        target_type=AUTH_SESSION_TARGET,
        actor_scope="target_user",
    ),
    AUTH_MFA_TOTP_ENROLLED: _presenter(
        item_type="auth.mfa.totp.enrolled",
        title="Authenticator app enabled",
        description="Two-step verification is enabled for your account.",
        target_type=AUTH_TOTP_FACTOR_TARGET,
    ),
    AUTH_MFA_TOTP_DISABLED: _presenter(
        item_type="auth.mfa.totp.disabled",
        title="Authenticator app disabled",
        description="Two-step verification is disabled for your account.",
        target_type=AUTH_TOTP_FACTOR_TARGET,
    ),
    AUTH_MFA_RECOVERY_CODES_REGENERATED: _presenter(
        item_type="auth.mfa.recovery.codes.regenerated",
        title="Recovery codes regenerated",
        description="Your previous recovery codes were replaced.",
        target_type=ACCOUNT_TARGET,
    ),
    AUTH_PASSWORD_INITIAL_SET: _presenter(
        item_type=AUTH_PASSWORD_INITIAL_SET,
        title="Password set",
        description="Your COMPASS account password was created.",
        target_type=ACCOUNT_TARGET,
    ),
    AUTH_PASSWORD_RESET: _presenter(
        item_type=AUTH_PASSWORD_RESET,
        title="Password reset",
        description="Your COMPASS account password was changed using account recovery.",
        target_type=ACCOUNT_TARGET,
    ),
    AUTH_TRUSTED_SESSION_CREATED: _presenter(
        item_type="auth.trusted.session.created",
        title="Trusted browser added",
        description="This browser can skip MFA for future sign-ins.",
        target_type=AUTH_TRUSTED_SESSION_TARGET,
    ),
    AUTH_TRUSTED_SESSION_REVOKED: _presenter(
        item_type="auth.trusted.session.revoked",
        title="Trusted browser removed",
        description="A trusted browser can no longer skip MFA.",
        target_type=AUTH_TRUSTED_SESSION_TARGET,
        actor_scope="target_user",
    ),
}


# Security Activity is intentionally narrower in meaning but includes selected historical
# authentication state changes that are useful when reviewing account security.
SECURITY_ACTIVITY_PRESENTERS: dict[str, ActivityPresenter] = {
    action: presenter
    for action, presenter in MY_ACTIVITY_PRESENTERS.items()
    if action != ACCOUNT_CREATED
}
SECURITY_ACTIVITY_PRESENTERS.update(
    {
        AUTH_LOGIN_FAILED: _presenter(
            item_type="auth.login.failed",
            title="Unsuccessful sign-in attempt",
            description="An unsuccessful sign-in attempt was detected.",
            target_type=ACCOUNT_TARGET,
            visible_outcomes=_DENIED,
        ),
        AUTH_SESSION_CREATED: _presenter(
            item_type="auth.session.created",
            title="New session created",
            description="A new COMPASS session was created for your account.",
            target_type=AUTH_SESSION_TARGET,
        ),
        AUTH_MFA_RECOVERY_CODE_USED: _presenter(
            item_type="auth.mfa.recovery.code.used",
            title="Recovery code used",
            description="A recovery code was used to verify your sign-in.",
            target_type=AUTH_RECOVERY_CODE_TARGET,
        ),
    }
)

# Short aliases make the closed-world nature of the two public projections obvious to callers.
ACTIVITY_PRESENTERS = MY_ACTIVITY_PRESENTERS

__all__ = [
    "ACCOUNT_TARGET",
    "ACTIVITY_PRESENTERS",
    "AUTH_RECOVERY_CODE_TARGET",
    "AUTH_SESSION_TARGET",
    "AUTH_TOTP_FACTOR_TARGET",
    "AUTH_TRUSTED_SESSION_TARGET",
    "ActivityItem",
    "ActivityPresenter",
    "MY_ACTIVITY_PRESENTERS",
    "SECURITY_ACTIVITY_PRESENTERS",
]
