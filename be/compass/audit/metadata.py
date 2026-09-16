"""Small, explicit metadata validation for audit events.

This is a shape and size guard, not a secret scanner. Audit call sites remain responsible for
choosing metadata that is safe and appropriate for the audit store.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from typing import Any

MAX_METADATA_BYTES = 8_192
MAX_METADATA_DEPTH = 4
MAX_METADATA_LIST_ITEMS = 64
MAX_METADATA_STRING_LENGTH = 1_024

_SENSITIVE_KEY_FRAGMENTS = (
    "access_key",
    "api_key",
    "authorization",
    "client_secret",
    "cookie",
    "credential",
    "otp",
    "password",
    "recovery",
    "secret",
    "session",
    "token",
    "totp",
    "turnstile",
)
_SENSITIVE_KEY_NAMES = frozenset(
    {
        "counseling_notes",
        "health_details",
        "inventory_contents",
        "medical_details",
        "narrative",
        "request_body",
        "request_payload",
        "response_body",
        "response_payload",
    }
)


def _validate_value(value: Any, *, path: str, depth: int) -> Any:
    if depth > MAX_METADATA_DEPTH:
        raise ValueError("audit metadata is nested too deeply")

    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str) and len(value) > MAX_METADATA_STRING_LENGTH:
            raise ValueError(f"audit metadata value at {path} is too long")
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"audit metadata value at {path} must be finite")
        return value

    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, nested_value in value.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError(f"audit metadata key at {path} must be a non-empty string")
            if len(key) > 128 or any(
                ord(character) < 32 or ord(character) == 127 for character in key
            ):
                raise ValueError(f"audit metadata key at {path} contains invalid characters")
            key_name = key.casefold().replace("-", "_")
            if key_name in _SENSITIVE_KEY_NAMES or any(
                fragment in key_name for fragment in _SENSITIVE_KEY_FRAGMENTS
            ):
                raise ValueError(f"audit metadata key {key!r} is not allowed for sensitive data")
            child_path = f"{path}.{key}" if path else key
            normalized[key] = _validate_value(nested_value, path=child_path, depth=depth + 1)
        return normalized

    if isinstance(value, list):
        if len(value) > MAX_METADATA_LIST_ITEMS:
            raise ValueError(f"audit metadata list at {path} is too long")
        return [
            _validate_value(nested_value, path=f"{path}[{index}]", depth=depth + 1)
            for index, nested_value in enumerate(value)
        ]

    raise ValueError(
        f"audit metadata value at {path or 'root'} must contain only JSON-compatible values"
    )


def validate_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a JSON-compatible metadata copy subject to the audit size/shape limits."""

    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise ValueError("audit metadata must be a JSON object")

    normalized = _validate_value(metadata, path="", depth=0)
    try:
        encoded = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        encoded_size = len(encoded.encode("utf-8"))
    except (TypeError, UnicodeError, ValueError) as exc:
        raise ValueError("audit metadata must be JSON serializable") from exc
    if encoded_size > MAX_METADATA_BYTES:
        raise ValueError(f"audit metadata must be at most {MAX_METADATA_BYTES} bytes")
    return normalized
