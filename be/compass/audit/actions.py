"""Stable audit action codes used by the current COMPASS foundation."""

ACCOUNT_CREATED = "account.created"
ACCOUNT_UPDATED = "account.updated"
ACCOUNT_DISABLED = "account.disabled"
ACCOUNT_ENABLED = "account.enabled"
ACCOUNT_ROLE_CHANGED = "account.role.changed"
ACCOUNT_DESIGNATION_ASSIGNED = "account.designation.assigned"
ACCOUNT_DESIGNATION_REMOVED = "account.designation.removed"
ACCOUNT_CAPABILITY_OVERRIDE_SET = "account.capability.override.set"
ACCOUNT_CAPABILITY_OVERRIDE_REMOVED = "account.capability.override.removed"
ACCOUNT_MFA_RESET = "account.mfa.reset"
IDENTITY_POLICY_SYNCED = "identity.policy.synced"

__all__ = [
    "ACCOUNT_CREATED",
    "ACCOUNT_UPDATED",
    "ACCOUNT_DISABLED",
    "ACCOUNT_ENABLED",
    "ACCOUNT_ROLE_CHANGED",
    "ACCOUNT_DESIGNATION_ASSIGNED",
    "ACCOUNT_DESIGNATION_REMOVED",
    "ACCOUNT_CAPABILITY_OVERRIDE_SET",
    "ACCOUNT_CAPABILITY_OVERRIDE_REMOVED",
    "ACCOUNT_MFA_RESET",
    "IDENTITY_POLICY_SYNCED",
]
