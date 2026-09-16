"""Explicit, synchronous COMPASS Audit Trail APIs."""

from __future__ import annotations


def record_event(*args, **kwargs):
    """Lazily delegate to the canonical audit recording service."""

    from compass.audit.services import record_event as _record_event

    return _record_event(*args, **kwargs)


record = record_event

__all__ = ["AuditContext", "AuditEvent", "record", "record_event"]


def __getattr__(name: str):
    if name == "AuditContext":
        from compass.audit.context import AuditContext

        return AuditContext
    if name == "AuditEvent":
        from compass.audit.models import AuditEvent

        return AuditEvent
    raise AttributeError(name)
