"""Thin Django Ninja routes for purpose-built administrative account management."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import NoReturn
from uuid import UUID

from ninja import Router, Schema, Status
from pydantic import ConfigDict

from compass.accounts.models import UserCapabilityOverride
from compass.accounts.policy import CAPABILITY_CODES, DESIGNATION_CODES, ROLE_CODES
from compass.audit.context import AuditContext
from compass.authentication.api import session_auth
from compass.authentication.sessions import RecentMFARequired, require_recent_mfa
from compass.common.api import response_with_errors
from compass.common.errors import APIError

from .services import (
    DEFAULT_PAGE_SIZE,
    AccountManagementError,
    AccountNotFound,
    DuplicateEmail,
    InvalidManagementInput,
    LastAccountManagerError,
    ManagementConfigurationError,
    ManagementNotAuthorized,
    OrganizationRelationshipConflict,
    PaginationError,
    SelfTargetForbidden,
    assign_designation,
    change_role,
    create_account,
    get_account,
    list_accounts,
    list_capability_overrides,
    list_designations,
    remove_capability_override,
    remove_designation,
    reset_account_mfa,
    revoke_account_sessions,
    revoke_account_trusted_sessions,
    serialize_account,
    set_account_active,
    set_capability_override,
    update_identity,
)

router = Router(tags=["accounts"])


def _code_enum(name: str, codes: frozenset[str]) -> type[Enum]:
    members = {code.replace(".", "_").replace("-", "_").upper(): code for code in sorted(codes)}
    return Enum(name, members, module=__name__, type=str)


RoleCode = _code_enum("RoleCode", ROLE_CODES)
DesignationCode = _code_enum("DesignationCode", DESIGNATION_CODES)
CapabilityCode = _code_enum("CapabilityCode", CAPABILITY_CODES)


class StrictSchema(Schema):
    model_config = ConfigDict(extra="forbid")


class AccountSummaryResponse(StrictSchema):
    id: UUID
    email: str
    first_name: str
    middle_name: str
    last_name: str
    suffix: str
    full_name: str
    role: RoleCode
    designations: list[DesignationCode]
    is_active: bool
    created_at: datetime


class AccountDetailResponse(AccountSummaryResponse):
    updated_at: datetime
    password_configured: bool
    mfa_enabled: bool


class AccountListResponse(StrictSchema):
    items: list[AccountSummaryResponse]
    page: int
    page_size: int
    has_next: bool


class AccountCreateRequest(StrictSchema):
    email: str
    first_name: str
    last_name: str
    role: RoleCode
    middle_name: str = ""
    suffix: str = ""
    is_active: bool = True


class IdentityUpdateRequest(StrictSchema):
    email: str | None = None
    first_name: str | None = None
    middle_name: str | None = None
    last_name: str | None = None
    suffix: str | None = None


class RoleUpdateRequest(StrictSchema):
    role: RoleCode


class DesignationListResponse(StrictSchema):
    designations: list[DesignationCode]


class CapabilityOverrideCreateRequest(StrictSchema):
    effect: UserCapabilityOverride.Effect
    reason: str
    expires_at: datetime | None = None


class CapabilityOverrideCreatorResponse(StrictSchema):
    id: UUID
    email: str
    full_name: str


class CapabilityOverrideResponse(StrictSchema):
    capability: CapabilityCode
    effect: UserCapabilityOverride.Effect
    reason: str
    expires_at: datetime | None
    created_at: datetime
    created_by: CapabilityOverrideCreatorResponse | None


class CapabilityOverrideListResponse(StrictSchema):
    overrides: list[CapabilityOverrideResponse]


class OverrideRemovalResponse(StrictSchema):
    removed: bool


class RevocationResponse(StrictSchema):
    revoked_count: int


class MFAResetResponse(StrictSchema):
    reset: bool
    revoked_session_count: int
    revoked_trusted_session_count: int


def _require_management(request, *, recent_mfa: bool) -> None:
    user = request.auth_user
    if not user.has_capability("accounts.manage"):
        raise APIError(
            403,
            "permission_denied",
            "The accounts.manage capability is required.",
        )
    if recent_mfa:
        try:
            require_recent_mfa(request.auth_session)
        except RecentMFARequired as exc:
            raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc


def _raise_management_error(exc: AccountManagementError) -> NoReturn:
    if isinstance(exc, AccountNotFound):
        raise APIError(404, "account_not_found", "The requested account was not found.") from exc
    if isinstance(exc, DuplicateEmail):
        raise APIError(409, "email_in_use", "An account with this email already exists.") from exc
    if isinstance(exc, LastAccountManagerError):
        raise APIError(
            409,
            "last_account_manager",
            "The operation must leave at least one active account manager.",
        ) from exc
    if isinstance(exc, OrganizationRelationshipConflict):
        raise APIError(
            409,
            "organization_relationship_conflict",
            str(exc),
        ) from exc
    if isinstance(exc, SelfTargetForbidden):
        raise APIError(
            403,
            "self_target_forbidden",
            "This administrative operation cannot target the acting administrator.",
        ) from exc
    if isinstance(exc, ManagementNotAuthorized):
        raise APIError(
            403, "permission_denied", "The accounts.manage capability is required."
        ) from exc
    if isinstance(exc, ManagementConfigurationError):
        raise APIError(
            503,
            "identity_policy_unavailable",
            "The canonical identity policy is temporarily unavailable.",
        ) from exc
    if isinstance(exc, (InvalidManagementInput, PaginationError)):
        raise APIError(422, "invalid_account_request", str(exc)) from exc
    raise APIError(
        500, "internal_error", "The account-management operation could not be completed."
    ) from exc


def _detail(user_id) -> dict[str, object]:
    return serialize_account(get_account(user_id=user_id, detail=True), detail=True)


def _context(request) -> AuditContext:
    return AuditContext.from_request(request, actor=request.auth_user)


@router.get(
    "",
    response=response_with_errors(AccountListResponse, 401, 403, 422),
    auth=session_auth,
    operation_id="accountsList",
    summary="List managed accounts",
)
def accounts(
    request,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    role: RoleCode | None = None,
    is_active: bool | None = None,
    designation: DesignationCode | None = None,
    search: str | None = None,
):
    _require_management(request, recent_mfa=False)
    try:
        result = list_accounts(
            page=page,
            page_size=page_size,
            role=role.value if role is not None else None,
            is_active=is_active,
            designation=designation.value if designation is not None else None,
            search=search,
        )
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return {
        "items": [serialize_account(user) for user in result.items],
        "page": result.page,
        "page_size": result.page_size,
        "has_next": result.has_next,
    }


@router.post(
    "",
    response=response_with_errors(
        AccountDetailResponse,
        401,
        403,
        409,
        422,
        503,
        success_status=201,
    ),
    auth=session_auth,
    operation_id="accountsCreate",
    summary="Create a managed account",
)
def account_create(request, payload: AccountCreateRequest):
    _require_management(request, recent_mfa=True)
    try:
        user = create_account(
            actor=request.auth_user,
            actor_session=request.auth_session,
            context=_context(request),
            email=payload.email,
            first_name=payload.first_name,
            middle_name=payload.middle_name,
            last_name=payload.last_name,
            suffix=payload.suffix,
            role=payload.role.value,
            is_active=payload.is_active,
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return Status(201, _detail(user.pk))


@router.patch(
    "/{user_id}/identity",
    response=response_with_errors(AccountDetailResponse, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="accountsUpdateIdentity",
    summary="Update managed account identity",
)
def account_identity(request, user_id: UUID, payload: IdentityUpdateRequest):
    _require_management(request, recent_mfa=True)
    try:
        update_identity(
            actor=request.auth_user,
            actor_session=request.auth_session,
            target_id=user_id,
            context=_context(request),
            changes=payload.model_dump(exclude_unset=True),
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return _detail(user_id)


@router.post(
    "/{user_id}/disable",
    response=response_with_errors(AccountDetailResponse, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="accountsDisable",
    summary="Disable a managed account",
)
def account_disable(request, user_id: UUID):
    _require_management(request, recent_mfa=True)
    try:
        set_account_active(
            actor=request.auth_user,
            actor_session=request.auth_session,
            target_id=user_id,
            context=_context(request),
            is_active=False,
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return _detail(user_id)


@router.post(
    "/{user_id}/enable",
    response=response_with_errors(AccountDetailResponse, 401, 403, 404, 422),
    auth=session_auth,
    operation_id="accountsEnable",
    summary="Enable a managed account",
)
def account_enable(request, user_id: UUID):
    _require_management(request, recent_mfa=True)
    try:
        set_account_active(
            actor=request.auth_user,
            actor_session=request.auth_session,
            target_id=user_id,
            context=_context(request),
            is_active=True,
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return _detail(user_id)


@router.put(
    "/{user_id}/role",
    response=response_with_errors(AccountDetailResponse, 401, 403, 404, 409, 422, 503),
    auth=session_auth,
    operation_id="accountsChangeRole",
    summary="Change a managed account role",
)
def account_role(request, user_id: UUID, payload: RoleUpdateRequest):
    _require_management(request, recent_mfa=True)
    try:
        change_role(
            actor=request.auth_user,
            actor_session=request.auth_session,
            target_id=user_id,
            context=_context(request),
            role=payload.role.value,
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return _detail(user_id)


@router.get(
    "/{user_id}/designations",
    response=response_with_errors(DesignationListResponse, 401, 403, 404, 422),
    auth=session_auth,
    operation_id="accountsListDesignations",
    summary="List managed account designations",
)
def account_designations(request, user_id: UUID):
    _require_management(request, recent_mfa=False)
    try:
        designations = list_designations(user_id=user_id)
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return {"designations": designations}


@router.post(
    "/{user_id}/designations/{designation_code}",
    response=response_with_errors(AccountDetailResponse, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="accountsAssignDesignation",
    summary="Assign a managed account designation",
)
def account_designation_assign(request, user_id: UUID, designation_code: DesignationCode):
    _require_management(request, recent_mfa=True)
    try:
        assign_designation(
            actor=request.auth_user,
            actor_session=request.auth_session,
            target_id=user_id,
            context=_context(request),
            designation=designation_code.value,
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return _detail(user_id)


@router.delete(
    "/{user_id}/designations/{designation_code}",
    response=response_with_errors(AccountDetailResponse, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="accountsRemoveDesignation",
    summary="Remove a managed account designation",
)
def account_designation_remove(request, user_id: UUID, designation_code: DesignationCode):
    _require_management(request, recent_mfa=True)
    try:
        remove_designation(
            actor=request.auth_user,
            actor_session=request.auth_session,
            target_id=user_id,
            context=_context(request),
            designation=designation_code.value,
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return _detail(user_id)


@router.get(
    "/{user_id}/capability-overrides",
    response=response_with_errors(CapabilityOverrideListResponse, 401, 403, 404, 422),
    auth=session_auth,
    operation_id="accountsListCapabilityOverrides",
    summary="List managed account capability overrides",
)
def account_capability_overrides(request, user_id: UUID):
    _require_management(request, recent_mfa=False)
    try:
        overrides = list_capability_overrides(user_id=user_id)
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return {"overrides": overrides}


@router.put(
    "/{user_id}/capability-overrides/{capability_code}",
    response=response_with_errors(CapabilityOverrideResponse, 401, 403, 404, 409, 422, 503),
    auth=session_auth,
    operation_id="accountsSetCapabilityOverride",
    summary="Set a managed account capability override",
)
def account_capability_override_set(
    request,
    user_id: UUID,
    capability_code: CapabilityCode,
    payload: CapabilityOverrideCreateRequest,
):
    _require_management(request, recent_mfa=True)
    try:
        result = set_capability_override(
            actor=request.auth_user,
            actor_session=request.auth_session,
            target_id=user_id,
            context=_context(request),
            capability=capability_code.value,
            effect=payload.effect,
            reason=payload.reason,
            expires_at=payload.expires_at,
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    assert result.override is not None
    return {
        "capability": result.override.capability.code,
        "effect": result.override.effect,
        "reason": result.override.reason,
        "expires_at": result.override.expires_at,
        "created_at": result.override.created_at,
        "created_by": {
            "id": result.override.created_by.pk,
            "email": result.override.created_by.email,
            "full_name": result.override.created_by.get_full_name(),
        }
        if result.override.created_by is not None
        else None,
    }


@router.delete(
    "/{user_id}/capability-overrides/{capability_code}",
    response=response_with_errors(OverrideRemovalResponse, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="accountsRemoveCapabilityOverride",
    summary="Remove a managed account capability override",
)
def account_capability_override_remove(request, user_id: UUID, capability_code: CapabilityCode):
    _require_management(request, recent_mfa=True)
    try:
        result = remove_capability_override(
            actor=request.auth_user,
            actor_session=request.auth_session,
            target_id=user_id,
            context=_context(request),
            capability=capability_code.value,
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return {"removed": result.changed}


@router.post(
    "/{user_id}/security/revoke-sessions",
    response=response_with_errors(RevocationResponse, 401, 403, 404, 422),
    auth=session_auth,
    operation_id="accountsRevokeSessions",
    summary="Revoke all authentication sessions for a managed account",
)
def account_revoke_sessions(request, user_id: UUID):
    _require_management(request, recent_mfa=True)
    try:
        result = revoke_account_sessions(
            actor=request.auth_user,
            actor_session=request.auth_session,
            target_id=user_id,
            context=_context(request),
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return {"revoked_count": result.revoked_count}


@router.post(
    "/{user_id}/security/revoke-trusted-sessions",
    response=response_with_errors(RevocationResponse, 401, 403, 404, 422),
    auth=session_auth,
    operation_id="accountsRevokeTrustedSessions",
    summary="Revoke all trusted sessions for a managed account",
)
def account_revoke_trusted_sessions(request, user_id: UUID):
    _require_management(request, recent_mfa=True)
    try:
        result = revoke_account_trusted_sessions(
            actor=request.auth_user,
            actor_session=request.auth_session,
            target_id=user_id,
            context=_context(request),
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return {"revoked_count": result.revoked_count}


@router.post(
    "/{user_id}/security/reset-mfa",
    response=response_with_errors(MFAResetResponse, 401, 403, 404, 422),
    auth=session_auth,
    operation_id="accountsResetMfa",
    summary="Reset MFA for a managed account",
)
def account_reset_mfa(request, user_id: UUID):
    _require_management(request, recent_mfa=True)
    try:
        result = reset_account_mfa(
            actor=request.auth_user,
            actor_session=request.auth_session,
            target_id=user_id,
            context=_context(request),
        )
    except RecentMFARequired as exc:
        raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc
    except AccountManagementError as exc:
        _raise_management_error(exc)
    return {
        "reset": result.reset,
        "revoked_session_count": result.invalidation.revoked_session_count,
        "revoked_trusted_session_count": result.invalidation.revoked_trusted_session_count,
    }


@router.get(
    "/{user_id}",
    response=response_with_errors(AccountDetailResponse, 401, 403, 404, 422),
    auth=session_auth,
    operation_id="accountsGet",
    summary="Inspect a managed account",
)
def account_detail(request, user_id: UUID):
    _require_management(request, recent_mfa=False)
    try:
        return _detail(user_id)
    except AccountManagementError as exc:
        _raise_management_error(exc)


__all__ = [
    "AccountCreateRequest",
    "AccountDetailResponse",
    "AccountListResponse",
    "AccountSummaryResponse",
    "router",
]
