"""Consistent, non-debug API and Django error responses."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from django.http import Http404, HttpRequest, JsonResponse
from ninja.errors import AuthenticationError, AuthorizationError, HttpError, ValidationError

logger = logging.getLogger("compass.errors")


class APIError(Exception):
    """A safe, centrally rendered public API error."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        details: object | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers or {}


def _request_id(request: HttpRequest) -> str | None:
    return getattr(request, "request_id", None)


def error_response(
    request: HttpRequest,
    *,
    status: int,
    code: str,
    message: str,
    details: object | None = None,
) -> JsonResponse:
    error: dict[str, object] = {
        "code": code,
        "message": message,
        "request_id": _request_id(request),
    }
    if details is not None:
        error["details"] = details
    return JsonResponse({"error": error}, status=status)


def _safe_validation_details(errors: Iterable[object]) -> list[dict[str, object]]:
    safe: list[dict[str, object]] = []
    for item in errors:
        if not isinstance(item, dict):
            continue
        location = item.get("loc", ())
        if isinstance(location, (list, tuple)):
            safe_location = [str(part) for part in location[:5]]
        else:
            safe_location = [str(location)]
        safe.append(
            {
                "loc": safe_location,
                "message": str(item.get("msg", "Invalid value")),
                "type": str(item.get("type", "validation_error")),
            }
        )
    return safe


def register_exception_handlers(api) -> None:
    @api.exception_handler(APIError)
    def api_error(request, exc):
        payload: dict[str, object] = {
            "error": {
                "code": exc.code,
                "message": exc.message,
                "request_id": _request_id(request),
            }
        }
        if exc.details is not None:
            payload["error"]["details"] = exc.details  # type: ignore[index]
        response = api.create_response(request, payload, status=exc.status_code)
        for key, value in exc.headers.items():
            response[key] = value
        return response

    @api.exception_handler(AuthenticationError)
    def authentication_error(request, exc):
        return api.create_response(
            request,
            {
                "error": {
                    "code": "authentication_required",
                    "message": "Authentication is required.",
                    "request_id": _request_id(request),
                }
            },
            status=401,
        )

    @api.exception_handler(AuthorizationError)
    def authorization_error(request, exc):
        return api.create_response(
            request,
            {
                "error": {
                    "code": "permission_denied",
                    "message": "You do not have permission to perform this action.",
                    "request_id": _request_id(request),
                }
            },
            status=403,
        )

    @api.exception_handler(ValidationError)
    def validation_error(request, exc):
        return api.create_response(
            request,
            {
                "error": {
                    "code": "validation_error",
                    "message": "The request could not be validated.",
                    "request_id": _request_id(request),
                    "details": _safe_validation_details(getattr(exc, "errors", [])),
                }
            },
            status=422,
        )

    @api.exception_handler(HttpError)
    def http_error(request, exc):
        status = int(getattr(exc, "status_code", 400))
        return api.create_response(
            request,
            {
                "error": {
                    "code": "http_error",
                    "message": "The request could not be completed.",
                    "request_id": _request_id(request),
                }
            },
            status=status,
        )

    @api.exception_handler(Http404)
    def api_not_found(request, exc):
        return api.create_response(
            request,
            {
                "error": {
                    "code": "not_found",
                    "message": "The requested resource was not found.",
                    "request_id": _request_id(request),
                }
            },
            status=404,
        )

    @api.exception_handler(Exception)
    def unhandled_error(request, exc):
        logger.exception(
            "unhandled api exception",
            extra={"event": "unhandled_api_exception", "request_id": _request_id(request)},
        )
        return api.create_response(
            request,
            {
                "error": {
                    "code": "internal_error",
                    "message": "An internal error occurred.",
                    "request_id": _request_id(request),
                }
            },
            status=500,
        )


def django_bad_request(request, exception=None):
    return error_response(
        request,
        status=400,
        code="bad_request",
        message="The request could not be understood.",
    )


def django_permission_denied(request, exception=None):
    return error_response(
        request,
        status=403,
        code="permission_denied",
        message="You do not have permission to perform this action.",
    )


def django_not_found(request, exception=None):
    return error_response(
        request,
        status=404,
        code="not_found",
        message="The requested resource was not found.",
    )


def django_server_error(request):
    logger.error(
        "unhandled django exception",
        extra={"event": "unhandled_django_exception", "request_id": _request_id(request)},
    )
    return error_response(
        request,
        status=500,
        code="internal_error",
        message="An internal error occurred.",
    )
