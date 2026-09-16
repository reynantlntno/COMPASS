"""Thin authenticated routes for the self-only activity projections."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from ninja import Router, Schema

from compass.authentication.api import session_auth
from compass.common.api import response_with_errors
from compass.common.errors import APIError

from .projections import (
    DEFAULT_PAGE_SIZE,
    ActivityPaginationError,
    get_my_activity,
    get_security_activity,
)

router = Router(tags=["activity"])


class ActivityItemResponse(Schema):
    id: UUID
    type: str
    title: str
    description: str
    occurred_at: datetime


class ActivityPageResponse(Schema):
    items: list[ActivityItemResponse]
    page: int
    page_size: int
    has_next: bool


def _invalid_pagination(exc: ActivityPaginationError) -> None:
    raise APIError(422, "invalid_pagination", str(exc)) from exc


@router.get(
    "/activity",
    response=response_with_errors(ActivityPageResponse, 401, 422),
    auth=session_auth,
    operation_id="meListActivity",
    summary="View my activity",
)
def my_activity(request, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE):
    try:
        result = get_my_activity(
            user=request.auth_user,
            page=page,
            page_size=page_size,
        )
    except ActivityPaginationError as exc:
        _invalid_pagination(exc)
    return result.as_dict()


@router.get(
    "/security-activity",
    response=response_with_errors(ActivityPageResponse, 401, 422),
    auth=session_auth,
    operation_id="meListSecurityActivity",
    summary="View my security activity",
)
def security_activity(request, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE):
    try:
        result = get_security_activity(
            user=request.auth_user,
            page=page,
            page_size=page_size,
        )
    except ActivityPaginationError as exc:
        _invalid_pagination(exc)
    return result.as_dict()


__all__ = ["ActivityItemResponse", "ActivityPageResponse", "router"]
