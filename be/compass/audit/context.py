"""Explicit actor and request context used by the Audit Trail service."""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass

from compass.audit.models import AuditActorType
from compass.common.correlation import get_current_request_id, normalize_request_id
from compass.common.rate_limit import client_ip

MAX_USER_AGENT_SUMMARY_LENGTH = 256


def summarize_user_agent(value: str | None) -> str | None:
    """Collapse untrusted user-agent whitespace/control characters and cap its length."""

    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("user_agent_summary must be a string")
    safe = "".join(
        " " if ord(character) < 32 or ord(character) == 127 else character for character in value
    )
    safe = " ".join(safe.split())
    return safe[:MAX_USER_AGENT_SUMMARY_LENGTH] or None


def _normalize_request_id(value: str | uuid.UUID | None) -> str | None:
    if value is None:
        return get_current_request_id()
    normalized = normalize_request_id(str(value))
    if normalized is None:
        raise ValueError("request_id must be a canonical UUID")
    return normalized


def _normalize_ip_address(value: str | None) -> str | None:
    if value is None or value == "" or value == "unknown":
        return None
    if not isinstance(value, str):
        raise ValueError("ip_address must be an IP address")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("ip_address must be an IP address") from exc


def _choice_value(value: str | AuditActorType) -> str:
    return value.value if isinstance(value, AuditActorType) else value


@dataclass(frozen=True, slots=True, init=False)
class AuditContext:
    """Accountability context; it never reads request bodies or creates hidden global state."""

    actor: object | None
    actor_type: str
    request_id: str | None
    ip_address: str | None
    user_agent_summary: str | None

    def __init__(
        self,
        *,
        actor: object | None = None,
        actor_user: object | None = None,
        actor_type: str | AuditActorType | None = None,
        request_id: str | uuid.UUID | None = None,
        ip_address: str | None = None,
        user_agent_summary: str | None = None,
    ) -> None:
        if actor is not None and actor_user is not None and actor is not actor_user:
            raise ValueError("actor and actor_user must refer to the same object")
        selected_actor = actor if actor is not None else actor_user
        selected_type = _choice_value(actor_type) if actor_type is not None else None
        if selected_type is None:
            selected_type = (
                AuditActorType.USER if selected_actor is not None else AuditActorType.SYSTEM
            )
        if selected_type not in AuditActorType.values:
            raise ValueError("actor_type must be USER, SYSTEM, or ANONYMOUS")
        if selected_type == AuditActorType.USER and selected_actor is None:
            raise ValueError("USER audit context requires an actor")
        if selected_type != AuditActorType.USER and selected_actor is not None:
            raise ValueError("SYSTEM and ANONYMOUS audit contexts cannot have an actor")

        object.__setattr__(self, "actor", selected_actor)
        object.__setattr__(self, "actor_type", selected_type)
        object.__setattr__(self, "request_id", _normalize_request_id(request_id))
        object.__setattr__(self, "ip_address", _normalize_ip_address(ip_address))
        object.__setattr__(self, "user_agent_summary", summarize_user_agent(user_agent_summary))

    @property
    def actor_user(self) -> object | None:
        """Compatibility/readability alias for the model field name."""

        return self.actor

    @classmethod
    def user(cls, user, **kwargs) -> AuditContext:
        return cls(actor=user, actor_type=AuditActorType.USER, **kwargs)

    @classmethod
    def system(cls, **kwargs) -> AuditContext:
        return cls(actor_type=AuditActorType.SYSTEM, **kwargs)

    @classmethod
    def anonymous(cls, **kwargs) -> AuditContext:
        return cls(actor_type=AuditActorType.ANONYMOUS, **kwargs)

    @classmethod
    def from_request(cls, request, *, actor=None, actor_type=None) -> AuditContext:
        if actor is None:
            request_user = getattr(request, "user", None)
            if request_user is not None and getattr(request_user, "is_authenticated", False):
                actor = request_user

        if actor_type is None:
            actor_type = AuditActorType.USER if actor is not None else AuditActorType.ANONYMOUS

        headers = getattr(request, "headers", {})
        user_agent = headers.get("User-Agent") or request.META.get("HTTP_USER_AGENT")
        resolved_ip = client_ip(request)
        request_id = getattr(request, "request_id", None) or get_current_request_id()
        return cls(
            actor=actor,
            actor_type=actor_type,
            request_id=request_id,
            ip_address=resolved_ip,
            user_agent_summary=user_agent,
        )
