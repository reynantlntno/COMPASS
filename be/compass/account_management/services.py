"""Transactional services for COMPASS administrative account management."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from compass.accounts.models import (
    Capability,
    Designation,
    Role,
    User,
    UserCapabilityOverride,
    UserDesignation,
)
from compass.accounts.policy import CAPABILITY_CODES, DESIGNATION_CODES, ROLE_CODES
from compass.accounts.services import set_user_capability_override, user_has_capability
from compass.audit.actions import (
    ACCOUNT_CAPABILITY_OVERRIDE_REMOVED,
    ACCOUNT_CAPABILITY_OVERRIDE_SET,
    ACCOUNT_CREATED,
    ACCOUNT_DESIGNATION_ASSIGNED,
    ACCOUNT_DESIGNATION_REMOVED,
    ACCOUNT_DISABLED,
    ACCOUNT_ENABLED,
    ACCOUNT_MFA_RESET,
    ACCOUNT_ROLE_CHANGED,
    ACCOUNT_UPDATED,
)
from compass.audit.context import AuditContext
from compass.audit.models import AuditOutcome
from compass.audit.services import record_event
from compass.authentication.mfa import MFAResetResult, has_active_totp_factor, reset_totp_state
from compass.authentication.security import (
    AuthStateInvalidation,
    invalidate_auth_state_after_authority_change,
)
from compass.authentication.sessions import (
    RecentMFARequired,
    require_recent_mfa,
    revoke_all_auth_sessions,
    revoke_all_trusted_sessions,
)

ACCOUNT_MANAGE_CAPABILITY = "accounts.manage"
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 50
MAX_PAGE_NUMBER = 100_000


class AccountManagementError(RuntimeError):
    """Base class for expected administrative account-management failures."""


class ManagementNotAuthorized(AccountManagementError):
    """The actor does not currently have effective account-management authority."""


class AccountNotFound(AccountManagementError):
    """The requested account does not exist."""


class DuplicateEmail(AccountManagementError):
    """The requested email is already assigned to another account."""


class InvalidManagementInput(AccountManagementError):
    """The request asks for a noncanonical or otherwise invalid management state."""


class ManagementConfigurationError(AccountManagementError):
    """Canonical identity policy has not been synchronized into the database."""


class LastAccountManagerError(AccountManagementError):
    """The mutation would leave no active account with accounts.manage."""


class SelfTargetForbidden(AccountManagementError):
    """The requested administrative target is the actor and is unsafe for this operation."""


class PaginationError(AccountManagementError):
    """The requested account page is outside the supported bounds."""


class OrganizationRelationshipConflict(AccountManagementError):
    """The role change would invalidate an Organization relationship."""


@dataclass(frozen=True, slots=True)
class AccountPage:
    items: tuple[User, ...]
    page: int
    page_size: int
    has_next: bool


@dataclass(frozen=True, slots=True)
class MutationResult:
    user: User
    changed: bool


@dataclass(frozen=True, slots=True)
class OverrideMutationResult:
    override: UserCapabilityOverride | None
    changed: bool


@dataclass(frozen=True, slots=True)
class MFAResetMutationResult:
    reset: bool
    mfa: MFAResetResult
    invalidation: AuthStateInvalidation


@dataclass(frozen=True, slots=True)
class SecurityRevocationResult:
    revoked_count: int


def _validate_pagination(*, page: int, page_size: int) -> tuple[int, int]:
    if type(page) is not int or page < 1 or page > MAX_PAGE_NUMBER:
        raise PaginationError(f"page must be an integer between 1 and {MAX_PAGE_NUMBER}")
    if type(page_size) is not int or page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise PaginationError(f"page_size must be an integer between 1 and {MAX_PAGE_SIZE}")
    return page, page_size


def _canonical_code(value: str, *, allowed: frozenset[str], label: str) -> str:
    if not isinstance(value, str):
        raise InvalidManagementInput(f"{label} must be a canonical code")
    normalized = value.strip()
    if normalized not in allowed:
        raise InvalidManagementInput(f"unknown {label}: {normalized}")
    return normalized


def _canonical_role_code(value: str) -> str:
    return _canonical_code(value, allowed=ROLE_CODES, label="role")


def _canonical_designation_code(value: str) -> str:
    return _canonical_code(value, allowed=DESIGNATION_CODES, label="designation")


def _canonical_capability_code(value: str) -> str:
    return _canonical_code(value, allowed=CAPABILITY_CODES, label="capability")


def _clean_identity_text(
    field_name: str,
    value: str | None,
    *,
    required: bool = False,
    allow_none: bool = False,
) -> str:
    if value is None:
        if allow_none:
            return ""
        raise InvalidManagementInput(f"{field_name} is required")
    if not isinstance(value, str):
        raise InvalidManagementInput(f"{field_name} must be a string")
    normalized = value.strip()
    if required and not normalized:
        raise InvalidManagementInput(f"{field_name} is required")
    try:
        User._meta.get_field(field_name).clean(normalized, None)
    except ValidationError as exc:
        raise InvalidManagementInput(f"{field_name} is invalid") from exc
    return normalized


def _clean_email(value: str) -> str:
    try:
        return User.objects.clean_email(value)
    except (TypeError, ValueError) as exc:
        raise InvalidManagementInput("a valid email address is required") from exc


def _clean_expiry(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if timezone.is_naive(value):
        value = timezone.make_aware(value, timezone.get_current_timezone())
    if value <= timezone.now():
        raise InvalidManagementInput("expires_at must be in the future")
    return value


def _lock_management_mutex() -> None:
    """Serialize account mutations that can change effective manager authority."""

    try:
        Capability.objects.select_for_update().get(code=ACCOUNT_MANAGE_CAPABILITY)
    except Capability.DoesNotExist as exc:
        raise ManagementConfigurationError(
            "accounts.manage capability is not synchronized; run sync_identity_policy first"
        ) from exc
    # Keeping this as one small canonical policy-row lock serializes manager-count checks without
    # introducing a distributed lock.


def _lock_users(*, actor_id, target_id=None) -> tuple[User, User | None]:
    if not actor_id:
        raise ManagementNotAuthorized("a saved administrative actor is required")
    ids = {actor_id}
    if target_id is not None:
        ids.add(target_id)
    locked = (
        User.objects.select_for_update().select_related("role").filter(pk__in=ids).order_by("id")
    )
    users = {user.pk: user for user in locked}
    actor = users.get(actor_id)
    if actor is None:
        raise ManagementNotAuthorized("the administrative actor is unavailable")
    target = users.get(target_id) if target_id is not None else None
    if target_id is not None and target is None:
        raise AccountNotFound("the requested account was not found")
    return actor, target


def _assert_manager(actor: User) -> None:
    if not actor.is_active or not user_has_capability(actor, ACCOUNT_MANAGE_CAPABILITY):
        raise ManagementNotAuthorized("accounts.manage is required")


def _assert_recent_mfa(*, actor: User, actor_session) -> None:
    if getattr(actor_session, "user_id", None) != actor.pk:
        raise ManagementNotAuthorized("the step-up session does not belong to the actor")
    try:
        require_recent_mfa(actor_session)
    except RecentMFARequired:
        raise


@contextmanager
def _admin_mutation(*, actor: User, actor_session, target_id=None, authority_change: bool = False):
    with transaction.atomic():
        if authority_change:
            _lock_management_mutex()
        locked_actor, locked_target = _lock_users(actor_id=actor.pk, target_id=target_id)
        _assert_manager(locked_actor)
        _assert_recent_mfa(actor=locked_actor, actor_session=actor_session)
        yield locked_actor, locked_target


def _active_manager_count() -> int:
    count = 0
    candidates = User.objects.filter(is_active=True).select_related("role")
    for candidate in candidates:
        if user_has_capability(candidate, ACCOUNT_MANAGE_CAPABILITY):
            count += 1
    return count


def _ensure_active_manager_remains() -> None:
    if _active_manager_count() == 0:
        raise LastAccountManagerError(
            "the operation would leave no active account with accounts.manage"
        )


def _account_designation_codes(user: User) -> list[str]:
    return [designation.code for designation in user.designations.all()]


def serialize_account(user: User, *, detail: bool = False) -> dict[str, object]:
    """Return an allowlisted account representation with no credential-bearing fields."""

    payload: dict[str, object] = {
        "id": user.pk,
        "email": user.email,
        "first_name": user.first_name,
        "middle_name": user.middle_name,
        "last_name": user.last_name,
        "suffix": user.suffix,
        "full_name": user.get_full_name(),
        "role": user.role.code,
        "designations": _account_designation_codes(user),
        "is_active": user.is_active,
        "created_at": user.created_at,
    }
    if detail:
        payload.update(
            {
                "updated_at": user.updated_at,
                "password_configured": user.has_usable_password(),
                "mfa_enabled": has_active_totp_factor(user.pk),
            }
        )
    return payload


def get_account(*, user_id, detail: bool = False) -> User:
    user = (
        User.objects.select_related("role")
        .prefetch_related("designations")
        .filter(pk=user_id)
        .first()
    )
    if user is None:
        raise AccountNotFound("the requested account was not found")
    return user


def list_accounts(
    *,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    role: str | None = None,
    is_active: bool | None = None,
    designation: str | None = None,
    search: str | None = None,
) -> AccountPage:
    page, page_size = _validate_pagination(page=page, page_size=page_size)
    queryset = (
        User.objects.select_related("role")
        .prefetch_related("designations")
        .order_by("-created_at", "-id")
    )
    if role is not None:
        queryset = queryset.filter(role__code=_canonical_role_code(role))
    if is_active is not None:
        queryset = queryset.filter(is_active=is_active)
    if designation is not None:
        queryset = queryset.filter(
            designations__code=_canonical_designation_code(designation)
        ).distinct()
    if search is not None:
        if not isinstance(search, str):
            raise InvalidManagementInput("search must be a string")
        normalized_search = search.strip()
        if len(normalized_search) > 254:
            raise InvalidManagementInput("search is too long")
        if normalized_search:
            search_filter = (
                Q(email__icontains=normalized_search)
                | Q(first_name__icontains=normalized_search)
                | Q(middle_name__icontains=normalized_search)
                | Q(last_name__icontains=normalized_search)
            )
            queryset = queryset.filter(search_filter)

    offset = (page - 1) * page_size
    records = list(queryset[offset : offset + page_size + 1])
    has_next = len(records) > page_size
    return AccountPage(
        items=tuple(records[:page_size]),
        page=page,
        page_size=page_size,
        has_next=has_next,
    )


def list_designations(*, user_id) -> list[str]:
    user = get_account(user_id=user_id)
    return list(user.designations.order_by("code").values_list("code", flat=True))


def _override_payload(override: UserCapabilityOverride) -> dict[str, object]:
    creator = override.created_by
    return {
        "capability": override.capability.code,
        "effect": override.effect,
        "reason": override.reason,
        "expires_at": override.expires_at,
        "created_at": override.created_at,
        "created_by": (
            {
                "id": creator.pk,
                "email": creator.email,
                "full_name": creator.get_full_name(),
            }
            if creator is not None
            else None
        ),
    }


def list_capability_overrides(*, user_id) -> list[dict[str, object]]:
    get_account(user_id=user_id)
    overrides = UserCapabilityOverride.objects.filter(user_id=user_id).select_related(
        "capability", "created_by"
    )
    return [_override_payload(override) for override in overrides.order_by("capability__code")]


def create_account(
    *,
    actor: User,
    actor_session,
    context: AuditContext,
    email: str,
    first_name: str,
    last_name: str,
    role: str,
    middle_name: str = "",
    suffix: str = "",
    is_active: bool = True,
) -> User:
    cleaned_email = _clean_email(email)
    cleaned_first_name = _clean_identity_text("first_name", first_name, required=True)
    cleaned_last_name = _clean_identity_text("last_name", last_name, required=True)
    cleaned_middle_name = _clean_identity_text("middle_name", middle_name, allow_none=True)
    cleaned_suffix = _clean_identity_text("suffix", suffix, allow_none=True)
    role_code = _canonical_role_code(role)

    with transaction.atomic():
        _lock_management_mutex()
        locked_actor, _ = _lock_users(actor_id=actor.pk)
        _assert_manager(locked_actor)
        _assert_recent_mfa(actor=locked_actor, actor_session=actor_session)
        role_record = Role.objects.filter(code=role_code).first()
        if role_record is None:
            raise ManagementConfigurationError(
                "the requested canonical role is not synchronized; run sync_identity_policy first"
            )
        try:
            with transaction.atomic():
                user = User.objects.create_user(
                    email=cleaned_email,
                    password=None,
                    role=role_record,
                    first_name=cleaned_first_name,
                    middle_name=cleaned_middle_name,
                    last_name=cleaned_last_name,
                    suffix=cleaned_suffix,
                    is_active=is_active,
                )
        except IntegrityError as exc:
            raise DuplicateEmail("an account with this email already exists") from exc
        record_event(
            context=context,
            action=ACCOUNT_CREATED,
            outcome=AuditOutcome.SUCCESS,
            target_type="accounts.user",
            target_id=user.pk,
            metadata={"role": role_code},
        )
    return user


def update_identity(
    *,
    actor: User,
    actor_session,
    target_id,
    context: AuditContext,
    changes: Mapping[str, object],
) -> MutationResult:
    allowed_fields = ("email", "first_name", "middle_name", "last_name", "suffix")
    unknown_fields = set(changes) - set(allowed_fields)
    if unknown_fields:
        raise InvalidManagementInput("identity updates contain unsupported fields")
    if not changes:
        raise InvalidManagementInput("at least one identity field is required")

    with _admin_mutation(
        actor=actor,
        actor_session=actor_session,
        target_id=target_id,
        authority_change=False,
    ) as (_locked_actor, target):
        assert target is not None
        normalized: dict[str, object] = {}
        for field_name in allowed_fields:
            if field_name not in changes:
                continue
            value = changes[field_name]
            if field_name == "email":
                normalized[field_name] = _clean_email(value)  # type: ignore[arg-type]
            elif field_name in {"first_name", "last_name"}:
                normalized[field_name] = _clean_identity_text(
                    field_name,
                    value,  # type: ignore[arg-type]
                    required=True,
                )
            else:
                normalized[field_name] = _clean_identity_text(
                    field_name,
                    value,  # type: ignore[arg-type]
                    allow_none=True,
                )
        changed_fields = [
            field_name
            for field_name in allowed_fields
            if field_name in normalized and getattr(target, field_name) != normalized[field_name]
        ]
        if not changed_fields:
            return MutationResult(user=target, changed=False)

        previous_email = target.email
        for field_name in changed_fields:
            setattr(target, field_name, normalized[field_name])
        try:
            with transaction.atomic():
                target.save(update_fields=[*changed_fields, "updated_at"])
        except IntegrityError as exc:
            raise DuplicateEmail("an account with this email already exists") from exc

        if "email" in changed_fields:
            invalidate_auth_state_after_authority_change(
                user_id=target.pk,
                context=context,
                reason="email_changed",
                invalidate_email_security_challenges=True,
                previous_email=previous_email,
            )
        record_event(
            context=context,
            action=ACCOUNT_UPDATED,
            outcome=AuditOutcome.SUCCESS,
            target_type="accounts.user",
            target_id=target.pk,
            metadata={"changed_fields": changed_fields},
        )
        return MutationResult(user=target, changed=True)


def set_account_active(
    *,
    actor: User,
    actor_session,
    target_id,
    context: AuditContext,
    is_active: bool,
) -> MutationResult:
    with _admin_mutation(
        actor=actor,
        actor_session=actor_session,
        target_id=target_id,
        authority_change=True,
    ) as (_locked_actor, target):
        assert target is not None
        if target.pk == actor.pk and not is_active:
            raise SelfTargetForbidden("an administrator cannot disable their own account")
        if target.is_active == is_active:
            if not is_active:
                invalidate_auth_state_after_authority_change(
                    user_id=target.pk,
                    context=context,
                    reason="account_disabled",
                    invalidate_email_security_challenges=True,
                )
            return MutationResult(user=target, changed=False)

        target.is_active = is_active
        target.save(update_fields=["is_active", "updated_at"])
        if not is_active:
            invalidate_auth_state_after_authority_change(
                user_id=target.pk,
                context=context,
                reason="account_disabled",
                invalidate_email_security_challenges=True,
            )
            _ensure_active_manager_remains()
            action = ACCOUNT_DISABLED
        else:
            action = ACCOUNT_ENABLED
        record_event(
            context=context,
            action=action,
            outcome=AuditOutcome.SUCCESS,
            target_type="accounts.user",
            target_id=target.pk,
            metadata={},
        )
        return MutationResult(user=target, changed=True)


def change_role(
    *,
    actor: User,
    actor_session,
    target_id,
    context: AuditContext,
    role: str,
) -> MutationResult:
    role_code = _canonical_role_code(role)
    with _admin_mutation(
        actor=actor,
        actor_session=actor_session,
        target_id=target_id,
        authority_change=True,
    ) as (_locked_actor, target):
        assert target is not None
        role_record = Role.objects.filter(code=role_code).first()
        if role_record is None:
            raise ManagementConfigurationError(
                "the requested canonical role is not synchronized; run sync_identity_policy first"
            )
        if target.role_id == role_record.pk:
            return MutationResult(user=target, changed=False)
        from compass.organization.services import (
            OrganizationRoleTransitionConflict,
            validate_role_transition,
        )

        try:
            validate_role_transition(user=target, new_role_code=role_code)
        except OrganizationRoleTransitionConflict as exc:
            raise OrganizationRelationshipConflict(str(exc)) from exc
        from_role = target.role.code
        target.role = role_record
        target.save(update_fields=["role", "updated_at"])
        if target.pk == actor.pk and not user_has_capability(target, ACCOUNT_MANAGE_CAPABILITY):
            raise SelfTargetForbidden(
                "an administrator cannot remove their own management authority"
            )
        _ensure_active_manager_remains()
        invalidate_auth_state_after_authority_change(
            user_id=target.pk,
            context=context,
            reason="role_changed",
        )
        record_event(
            context=context,
            action=ACCOUNT_ROLE_CHANGED,
            outcome=AuditOutcome.SUCCESS,
            target_type="accounts.user",
            target_id=target.pk,
            metadata={"from_role": from_role, "to_role": role_code},
        )
        return MutationResult(user=target, changed=True)


def assign_designation(
    *,
    actor: User,
    actor_session,
    target_id,
    context: AuditContext,
    designation: str,
) -> MutationResult:
    designation_code = _canonical_designation_code(designation)
    with _admin_mutation(
        actor=actor,
        actor_session=actor_session,
        target_id=target_id,
        authority_change=True,
    ) as (_locked_actor, target):
        assert target is not None
        if target.pk == actor.pk:
            raise SelfTargetForbidden("an administrator cannot change their own designations")
        designation_record = Designation.objects.filter(code=designation_code).first()
        if designation_record is None:
            raise ManagementConfigurationError(
                "the requested canonical designation is not synchronized; run "
                "sync_identity_policy first"
            )
        assignment = (
            UserDesignation.objects.select_for_update()
            .filter(
                user_id=target.pk,
                designation_id=designation_record.pk,
            )
            .first()
        )
        if assignment is not None:
            return MutationResult(user=target, changed=False)
        UserDesignation.objects.create(user=target, designation=designation_record)
        _ensure_active_manager_remains()
        invalidate_auth_state_after_authority_change(
            user_id=target.pk,
            context=context,
            reason="designation_assigned",
        )
        record_event(
            context=context,
            action=ACCOUNT_DESIGNATION_ASSIGNED,
            outcome=AuditOutcome.SUCCESS,
            target_type="accounts.user",
            target_id=target.pk,
            metadata={"designation": designation_code},
        )
        return MutationResult(user=target, changed=True)


def remove_designation(
    *,
    actor: User,
    actor_session,
    target_id,
    context: AuditContext,
    designation: str,
) -> MutationResult:
    designation_code = _canonical_designation_code(designation)
    with _admin_mutation(
        actor=actor,
        actor_session=actor_session,
        target_id=target_id,
        authority_change=True,
    ) as (_locked_actor, target):
        assert target is not None
        if target.pk == actor.pk:
            raise SelfTargetForbidden("an administrator cannot change their own designations")
        designation_record = Designation.objects.filter(code=designation_code).first()
        if designation_record is None:
            raise ManagementConfigurationError(
                "the requested canonical designation is not synchronized; run "
                "sync_identity_policy first"
            )
        assignment = (
            UserDesignation.objects.select_for_update()
            .filter(
                user_id=target.pk,
                designation_id=designation_record.pk,
            )
            .first()
        )
        if assignment is None:
            return MutationResult(user=target, changed=False)
        assignment.delete()
        _ensure_active_manager_remains()
        invalidate_auth_state_after_authority_change(
            user_id=target.pk,
            context=context,
            reason="designation_removed",
        )
        record_event(
            context=context,
            action=ACCOUNT_DESIGNATION_REMOVED,
            outcome=AuditOutcome.SUCCESS,
            target_type="accounts.user",
            target_id=target.pk,
            metadata={"designation": designation_code},
        )
        return MutationResult(user=target, changed=True)


def set_capability_override(
    *,
    actor: User,
    actor_session,
    target_id,
    context: AuditContext,
    capability: str,
    effect: UserCapabilityOverride.Effect | str,
    reason: str,
    expires_at: datetime | None = None,
) -> OverrideMutationResult:
    capability_code = _canonical_capability_code(capability)
    effect_value = effect.value if isinstance(effect, UserCapabilityOverride.Effect) else effect
    if effect_value not in UserCapabilityOverride.Effect.values:
        raise InvalidManagementInput("effect must be GRANT or REVOKE")
    if not isinstance(reason, str) or not reason.strip():
        raise InvalidManagementInput("reason is required for a capability override")
    cleaned_reason = reason.strip()
    try:
        UserCapabilityOverride._meta.get_field("reason").clean(cleaned_reason, None)
    except ValidationError as exc:
        raise InvalidManagementInput("reason is invalid") from exc
    cleaned_expiry = _clean_expiry(expires_at)

    with _admin_mutation(
        actor=actor,
        actor_session=actor_session,
        target_id=target_id,
        authority_change=True,
    ) as (locked_actor, target):
        assert target is not None
        if target.pk == locked_actor.pk:
            raise SelfTargetForbidden(
                "an administrator cannot change their own capability overrides"
            )
        capability_record = Capability.objects.filter(code=capability_code).first()
        if capability_record is None:
            raise ManagementConfigurationError(
                "the requested canonical capability is not synchronized; run "
                "sync_identity_policy first"
            )
        existing = (
            UserCapabilityOverride.objects.select_for_update()
            .filter(
                user_id=target.pk,
                capability_id=capability_record.pk,
            )
            .first()
        )
        if existing is not None and (
            existing.effect == effect_value
            and existing.reason == cleaned_reason
            and existing.expires_at == cleaned_expiry
            and existing.created_by_id == locked_actor.pk
        ):
            return OverrideMutationResult(override=existing, changed=False)
        override = set_user_capability_override(
            user=target,
            capability=capability_record,
            effect=effect_value,
            reason=cleaned_reason,
            expires_at=cleaned_expiry,
            created_by=locked_actor,
        )
        _ensure_active_manager_remains()
        invalidate_auth_state_after_authority_change(
            user_id=target.pk,
            context=context,
            reason="capability_override_changed",
        )
        record_event(
            context=context,
            action=ACCOUNT_CAPABILITY_OVERRIDE_SET,
            outcome=AuditOutcome.SUCCESS,
            target_type="accounts.user",
            target_id=target.pk,
            metadata={
                "capability": capability_code,
                "effect": effect_value,
                "has_expiry": cleaned_expiry is not None,
            },
        )
        return OverrideMutationResult(override=override, changed=True)


def remove_capability_override(
    *,
    actor: User,
    actor_session,
    target_id,
    context: AuditContext,
    capability: str,
) -> OverrideMutationResult:
    capability_code = _canonical_capability_code(capability)
    with _admin_mutation(
        actor=actor,
        actor_session=actor_session,
        target_id=target_id,
        authority_change=True,
    ) as (locked_actor, target):
        assert target is not None
        if target.pk == locked_actor.pk:
            raise SelfTargetForbidden(
                "an administrator cannot change their own capability overrides"
            )
        capability_record = Capability.objects.filter(code=capability_code).first()
        if capability_record is None:
            raise ManagementConfigurationError(
                "the requested canonical capability is not synchronized; run "
                "sync_identity_policy first"
            )
        override = (
            UserCapabilityOverride.objects.select_for_update()
            .filter(
                user_id=target.pk,
                capability_id=capability_record.pk,
            )
            .first()
        )
        if override is None:
            return OverrideMutationResult(override=None, changed=False)
        override.delete()
        _ensure_active_manager_remains()
        invalidate_auth_state_after_authority_change(
            user_id=target.pk,
            context=context,
            reason="capability_override_removed",
        )
        record_event(
            context=context,
            action=ACCOUNT_CAPABILITY_OVERRIDE_REMOVED,
            outcome=AuditOutcome.SUCCESS,
            target_type="accounts.user",
            target_id=target.pk,
            metadata={"capability": capability_code},
        )
        return OverrideMutationResult(override=override, changed=True)


def revoke_account_sessions(
    *,
    actor: User,
    actor_session,
    target_id,
    context: AuditContext,
) -> SecurityRevocationResult:
    with _admin_mutation(
        actor=actor,
        actor_session=actor_session,
        target_id=target_id,
        authority_change=False,
    ) as (_locked_actor, target):
        assert target is not None
        if target.pk == actor.pk:
            raise SelfTargetForbidden("use self-service session controls for your own sessions")
        count = revoke_all_auth_sessions(
            user_id=target.pk,
            context=context,
            reason="admin_revoked",
        )
        return SecurityRevocationResult(revoked_count=count)


def revoke_account_trusted_sessions(
    *,
    actor: User,
    actor_session,
    target_id,
    context: AuditContext,
) -> SecurityRevocationResult:
    with _admin_mutation(
        actor=actor,
        actor_session=actor_session,
        target_id=target_id,
        authority_change=False,
    ) as (_locked_actor, target):
        assert target is not None
        if target.pk == actor.pk:
            raise SelfTargetForbidden(
                "use self-service trusted-session controls for your own sessions"
            )
        count = revoke_all_trusted_sessions(
            user_id=target.pk,
            context=context,
            reason="admin_revoked",
        )
        return SecurityRevocationResult(revoked_count=count)


def reset_account_mfa(
    *,
    actor: User,
    actor_session,
    target_id,
    context: AuditContext,
) -> MFAResetMutationResult:
    with _admin_mutation(
        actor=actor,
        actor_session=actor_session,
        target_id=target_id,
        authority_change=False,
    ) as (_locked_actor, target):
        assert target is not None
        if target.pk == actor.pk:
            raise SelfTargetForbidden("use self-service MFA controls for your own MFA")
        mfa_result = reset_totp_state(user_id=target.pk)
        invalidation = invalidate_auth_state_after_authority_change(
            user_id=target.pk,
            context=context,
            reason="admin_mfa_reset",
        )
        if mfa_result.changed:
            record_event(
                context=context,
                action=ACCOUNT_MFA_RESET,
                outcome=AuditOutcome.SUCCESS,
                target_type="accounts.user",
                target_id=target.pk,
                metadata={},
            )
        return MFAResetMutationResult(
            reset=mfa_result.changed,
            mfa=mfa_result,
            invalidation=invalidation,
        )


__all__ = [
    "ACCOUNT_MANAGE_CAPABILITY",
    "AccountManagementError",
    "AccountNotFound",
    "AccountPage",
    "DEFAULT_PAGE_SIZE",
    "DuplicateEmail",
    "InvalidManagementInput",
    "LastAccountManagerError",
    "MAX_PAGE_NUMBER",
    "MAX_PAGE_SIZE",
    "MFAResetMutationResult",
    "ManagementConfigurationError",
    "ManagementNotAuthorized",
    "MutationResult",
    "OverrideMutationResult",
    "PaginationError",
    "SecurityRevocationResult",
    "SelfTargetForbidden",
    "assign_designation",
    "change_role",
    "create_account",
    "get_account",
    "list_accounts",
    "list_capability_overrides",
    "list_designations",
    "remove_capability_override",
    "remove_designation",
    "reset_account_mfa",
    "revoke_account_sessions",
    "revoke_account_trusted_sessions",
    "serialize_account",
    "set_account_active",
    "set_capability_override",
    "update_identity",
]
