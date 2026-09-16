"""Small, explicit environment parsing helpers used by settings."""

from __future__ import annotations

import os
from typing import cast

_MISSING = object()


def env[T](name: str, default: T | object = _MISSING) -> str | T:
    value = os.environ.get(name)
    if value is None or value == "":
        if default is _MISSING:
            raise ValueError(f"{name} is required")
        return cast(T, default)
    return value


def required_env(name: str) -> str:
    value = env(name)
    return cast(str, value)


def env_bool(name: str, default: bool) -> bool:
    raw = env(name, default)
    if isinstance(raw, bool):
        return raw
    normalized = str(raw).strip().lower()
    if normalized in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "f", "no", "n", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def env_int(name: str, default: int) -> int:
    raw = env(name, default)
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc


def env_float(name: str, default: float) -> float:
    raw = env(name, default)
    try:
        return float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc


def env_csv(name: str, default: list[str]) -> list[str]:
    raw = env(name, ",".join(default))
    if isinstance(raw, list):
        return raw
    return [item.strip() for item in str(raw).split(",") if item.strip()]
