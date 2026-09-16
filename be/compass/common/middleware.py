"""HTTP middleware for request correlation and safe completion logs."""

from __future__ import annotations

import logging
from time import monotonic

from django.http import HttpRequest, HttpResponse

from compass.common.correlation import (
    REQUEST_ID_HEADER,
    request_id_from_header,
    reset_current_request_id,
    set_current_request_id,
)

logger = logging.getLogger("compass.request")


class RequestContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request_id = request_id_from_header(request.headers.get(REQUEST_ID_HEADER))
        request.request_id = request_id
        token = set_current_request_id(request_id)
        started = monotonic()
        response: HttpResponse | None = None
        try:
            response = self.get_response(request)
            response[REQUEST_ID_HEADER] = request_id
            return response
        finally:
            extra = {
                "event": "request_completed",
                "request_id": request_id,
                "method": request.method,
                "path": request.path,
                "duration_ms": round((monotonic() - started) * 1000, 2),
                "status_code": response.status_code if response is not None else 500,
            }
            logger.info("request completed", extra=extra)
            reset_current_request_id(token)
