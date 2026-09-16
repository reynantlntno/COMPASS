"""Request and task correlation identifiers."""

from __future__ import annotations

import contextvars
import uuid

REQUEST_ID_HEADER = "X-Request-ID"
_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "compass_request_id", default=None
)


def normalize_request_id(value: str | None) -> str | None:
    """Accept only canonical UUID request IDs supplied by a client."""
    if not value or len(value) > 64:
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    normalized = str(parsed)
    return normalized if value.lower() == normalized else None


def new_request_id() -> str:
    return str(uuid.uuid4())


def request_id_from_header(value: str | None) -> str:
    return normalize_request_id(value) or new_request_id()


def set_current_request_id(value: str | None) -> contextvars.Token[str | None]:
    return _request_id.set(value)


def reset_current_request_id(token: contextvars.Token[str | None]) -> None:
    _request_id.reset(token)


def get_current_request_id() -> str | None:
    return _request_id.get()
