"""Small, canonical services for COMPASS capability evaluation."""

from __future__ import annotations

from datetime import datetime

from django.db.models import Q
from django.utils import timezone

from compass.accounts.models import (
    Capability,
    DesignationCapability,
    RoleCapability,
    User,
    UserCapabilityOverride,
)
from compass.accounts.policy import CAPABILITY_CODES


def effective_capabilities(user: User, *, at: datetime | None = None) -> frozenset[str]:
    """Return the active, scope-free capabilities effective for one account.

    Role and designation grants are collected first. Active account overrides are then applied,
    with revocations removed last so a revoke is deterministic even if bad data ever contains
    both effects. Unknown capability codes are never returned because policy is canonical in code.
    """

    if not getattr(user, "pk", None) or not getattr(user, "is_authenticated", False):
        return frozenset()
    if not getattr(user, "is_active", False):
        return frozenset()

    capability_codes: set[str] = set()
    role_id = getattr(user, "role_id", None)
    if role_id:
        capability_codes.update(
            RoleCapability.objects.filter(role_id=role_id).values_list(
                "capability__code", flat=True
            )
        )

    capability_codes.update(
        DesignationCapability.objects.filter(
            designation__user_assignments__user_id=user.pk
        ).values_list("capability__code", flat=True)
    )

    now = at if at is not None else timezone.now()
    granted: set[str] = set()
    revoked: set[str] = set()
    active_overrides = UserCapabilityOverride.objects.filter(user_id=user.pk).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=now)
    )
    for code, effect in active_overrides.values_list("capability__code", "effect"):
        if effect == UserCapabilityOverride.Effect.REVOKE:
            revoked.add(code)
        elif effect == UserCapabilityOverride.Effect.GRANT:
            granted.add(code)

    return frozenset(((capability_codes | granted) & CAPABILITY_CODES) - revoked)


def user_has_capability(
    user: User,
    capability_code: str,
    *,
    at: datetime | None = None,
) -> bool:
    """Return whether an active account has one canonical COMPASS capability."""

    if capability_code not in CAPABILITY_CODES:
        return False
    return capability_code in effective_capabilities(user, at=at)


def set_user_capability_override(
    *,
    user: User,
    capability: Capability | str,
    effect: UserCapabilityOverride.Effect | str,
    reason: str,
    expires_at: datetime | None = None,
    created_by: User | None = None,
) -> UserCapabilityOverride:
    """Create or replace the one explicit override for a user/capability pair."""

    if not getattr(user, "pk", None):
        raise ValueError("user must be saved before assigning a capability override")
    if isinstance(capability, str):
        try:
            capability = Capability.objects.get(code=capability)
        except Capability.DoesNotExist as exc:
            raise ValueError(f"unknown capability: {capability}") from exc
    if capability.pk is None:
        raise ValueError("capability must be saved before assigning an override")
    if capability.code not in CAPABILITY_CODES:
        raise ValueError(f"unknown capability: {capability.code}")
    if effect not in UserCapabilityOverride.Effect.values:
        raise ValueError("effect must be GRANT or REVOKE")
    cleaned_reason = reason.strip()
    if not cleaned_reason:
        raise ValueError("reason is required for a capability override")
    if created_by is not None and not getattr(created_by, "pk", None):
        raise ValueError("created_by must be saved when provided")

    override, _created = UserCapabilityOverride.objects.update_or_create(
        user=user,
        capability=capability,
        defaults={
            "effect": effect,
            "reason": cleaned_reason,
            "expires_at": expires_at,
            "created_by": created_by,
        },
    )
    return override
