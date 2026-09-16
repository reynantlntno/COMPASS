"""Validation rules for the committed COMPASS OpenAPI development contract."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

OPENAPI_VERSION = "3.1.0"
CURRENT_API_TAGS = frozenset({"health", "auth", "activity", "accounts", "organization"})
OPERATION_ID_PATTERN = re.compile(r"^[a-z][A-Za-z0-9]*$", re.ASCII)
OPERATION_ID_PREFIXES = {
    "health": "health",
    "auth": "auth",
    "activity": "me",
    "accounts": "accounts",
    "organization": "organization",
}
HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch"})


def iter_operations(schema: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield HTTP operations from an OpenAPI document in deterministic order."""

    for path, path_item in sorted(schema.get("paths", {}).items()):
        for method, operation in sorted(path_item.items()):
            if method in HTTP_METHODS and isinstance(operation, dict):
                yield method, path, operation


def validate_openapi_contract(schema: dict[str, Any]) -> None:
    """Raise ``ValueError`` when the public schema violates contract invariants."""

    problems: list[str] = []
    if schema.get("openapi") != OPENAPI_VERSION:
        problems.append(f"openapi must be {OPENAPI_VERSION}")
    tag_definitions = schema.get("tags")
    tag_names = (
        [tag.get("name") for tag in tag_definitions if isinstance(tag, dict)]
        if isinstance(tag_definitions, list)
        else []
    )
    if set(tag_names) != CURRENT_API_TAGS or len(tag_names) != len(CURRENT_API_TAGS):
        problems.append("top-level tags must define the approved current API domains")

    operation_ids: dict[str, tuple[str, str]] = {}
    operation_count = 0
    for method, path, operation in iter_operations(schema):
        operation_count += 1
        operation_id = operation.get("operationId")
        location = f"{method.upper()} {path}"
        if not isinstance(operation_id, str) or not operation_id:
            problems.append(f"{location} is missing operationId")
            continue
        if not OPERATION_ID_PATTERN.fullmatch(operation_id):
            problems.append(f"{location} has invalid operationId {operation_id!r}")
        previous = operation_ids.get(operation_id)
        if previous is not None:
            problems.append(
                f"operationId {operation_id!r} is used by {previous[0].upper()} {previous[1]} "
                f"and {location}"
            )
        else:
            operation_ids[operation_id] = (method, path)

        tags = operation.get("tags")
        if not isinstance(tags, list) or len(tags) != 1 or tags[0] not in CURRENT_API_TAGS:
            problems.append(f"{location} must have exactly one approved tag")
            continue
        expected_prefix = OPERATION_ID_PREFIXES[tags[0]]
        suffix = (
            operation_id[len(expected_prefix) :] if operation_id.startswith(expected_prefix) else ""
        )
        if not suffix or suffix[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            problems.append(
                f"{location} operationId {operation_id!r} must use the {expected_prefix}<Action> "
                "convention"
            )

    if operation_count == 0:
        problems.append("schema has no public HTTP operations")

    if problems:
        raise ValueError("Invalid COMPASS OpenAPI contract: " + "; ".join(problems))


__all__ = [
    "CURRENT_API_TAGS",
    "HTTP_METHODS",
    "OPENAPI_VERSION",
    "OPERATION_ID_PATTERN",
    "OPERATION_ID_PREFIXES",
    "iter_operations",
    "validate_openapi_contract",
]
