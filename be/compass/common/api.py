"""Shared public API schemas and response-contract helpers."""

from __future__ import annotations

from typing import Any

from ninja import Schema


class ValidationIssue(Schema):
    """A safe, normalized validation issue returned inside the error envelope."""

    loc: list[str]
    message: str
    type: str


class APIErrorDetail(Schema):
    """The stable error payload shared by all public API domains."""

    code: str
    message: str
    request_id: str | None = None
    details: list[ValidationIssue] | dict[str, Any] | None = None


class APIErrorResponse(Schema):
    """The standard COMPASS JSON error envelope."""

    error: APIErrorDetail


def response_with_errors(
    success_schema: Any,
    *error_statuses: int,
    success_status: int = 200,
) -> dict[int, Any]:
    """Build a response map without duplicating the shared error schema."""

    return {
        success_status: success_schema,
        **{status: APIErrorResponse for status in error_statuses},
    }


__all__ = [
    "APIErrorDetail",
    "APIErrorResponse",
    "ValidationIssue",
    "response_with_errors",
]
