"""The single canonical synchronous Audit Trail recording service."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime

from django.contrib.auth import get_user_model

from compass.audit.context import AuditContext
from compass.audit.metadata import validate_metadata
from compass.audit.models import (
    ACTION_RE,
    MAX_TARGET_ID_LENGTH,
    TARGET_TYPE_RE,
    AuditEvent,
    AuditOutcome,
)


def _normalize_choice(value: str | AuditOutcome) -> str:
    return value.value if isinstance(value, AuditOutcome) else value


def _validate_action(action: str) -> str:
    if not isinstance(action, str) or not ACTION_RE.fullmatch(action):
        raise ValueError("action must be a lowercase dotted identifier")
    return action


def _normalize_target(
    target_type: str | None,
    target_id: str | uuid.UUID | int | None,
) -> tuple[str | None, str | None]:
    normalized_type = target_type.strip() if isinstance(target_type, str) else target_type
    normalized_id = str(target_id).strip() if target_id is not None else None
    if normalized_type == "":
        normalized_type = None
    if normalized_id == "":
        normalized_id = None

    if (normalized_type is None) != (normalized_id is None):
        raise ValueError("target_type and target_id must be provided together")
    if normalized_type is None:
        return None, None
    if not TARGET_TYPE_RE.fullmatch(normalized_type):
        raise ValueError("target_type must be a lowercase dotted identifier")
    if len(normalized_id) > MAX_TARGET_ID_LENGTH or any(
        ord(character) < 32 or ord(character) == 127 for character in normalized_id
    ):
        raise ValueError("target_id contains invalid characters or is too long")
    return normalized_type, normalized_id


def record_event(
    *,
    context: AuditContext,
    action: str,
    outcome: str | AuditOutcome,
    target_type: str | None = None,
    target_id: str | uuid.UUID | int | None = None,
    metadata: Mapping[str, object] | None = None,
    occurred_at: datetime | None = None,
    using: str | None = None,
) -> AuditEvent:
    """Synchronously append one validated event to PostgreSQL.

    Callers should invoke this inside the same ``transaction.atomic()`` block as a successful
    state mutation. DENIED and relevant FAILED events may be recorded in their own transaction.
    """

    if not isinstance(context, AuditContext):
        raise TypeError("context must be an AuditContext")
    normalized_action = _validate_action(action)
    normalized_outcome = _normalize_choice(outcome)
    if normalized_outcome not in AuditOutcome.values:
        raise ValueError("outcome must be SUCCESS, DENIED, or FAILED")
    normalized_target_type, normalized_target_id = _normalize_target(target_type, target_id)
    normalized_metadata = validate_metadata(metadata)

    actor_user = None
    if context.actor_type == AuditEvent.ActorType.USER:
        user_model = get_user_model()
        if not isinstance(context.actor, user_model) or not getattr(context.actor, "pk", None):
            raise ValueError("USER audit context requires a saved COMPASS user")
        actor_user = context.actor

    event_kwargs = {
        "actor_type": context.actor_type,
        "actor_user": actor_user,
        "action": normalized_action,
        "outcome": normalized_outcome,
        "target_type": normalized_target_type,
        "target_id": normalized_target_id,
        "request_id": context.request_id,
        "ip_address": context.ip_address,
        "user_agent_summary": context.user_agent_summary,
        "metadata": normalized_metadata,
    }
    if occurred_at is not None:
        event_kwargs["occurred_at"] = occurred_at
    event = AuditEvent(**event_kwargs)
    if using is None:
        event.save()
    else:
        event.save(using=using)
    return event


record = record_event

__all__ = ["AuditContext", "record", "record_event"]
