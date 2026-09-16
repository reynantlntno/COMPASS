"""Reusable Redis boundary for idempotent state-changing operations.

This layer reserves a request once, compares future requests by fingerprint, and stores the
completed response for replay. It is intentionally not wired to any endpoint until a domain
operation defines its actor identity and response semantics.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Literal

import redis
from django.conf import settings

_COMPLETE_SCRIPT = """
local raw = redis.call('GET', KEYS[1])
if not raw then return -1 end
local record = cjson.decode(raw)
if record.owner_token ~= ARGV[1] then return 0 end
record.state = 'completed'
record.status_code = tonumber(ARGV[2])
record.content_type = ARGV[3]
record.body_b64 = ARGV[4]
redis.call('SET', KEYS[1], cjson.encode(record), 'EX', ARGV[5])
return 1
"""


class IdempotencyUnavailable(RuntimeError):
    """Raised when idempotency state cannot be read or written safely."""


class IdempotencyConflict(RuntimeError):
    """Raised when a key is reused for a different request."""


class IdempotencyOwnershipError(RuntimeError):
    """Raised when a caller tries to complete another request's reservation."""


@dataclass(frozen=True, slots=True)
class StoredResponse:
    status_code: int
    body: bytes
    content_type: str = "application/json"


@dataclass(frozen=True, slots=True)
class IdempotencyReservation:
    redis_key: str
    owner_token: str


@dataclass(frozen=True, slots=True)
class IdempotencyDecision:
    outcome: Literal["execute", "replay", "in_progress"]
    reservation: IdempotencyReservation | None = None
    response: StoredResponse | None = None


def request_fingerprint(*, method: str, route: str, query_string: str, body: bytes) -> str:
    canonical = b"\0".join(
        [method.upper().encode("utf-8"), route.encode("utf-8"), query_string.encode("utf-8"), body]
    )
    return hashlib.sha256(canonical).hexdigest()


class RedisIdempotencyStore:
    def __init__(
        self,
        client,
        *,
        key_prefix: str = "compass:idempotency",
        ttl_seconds: int = 86_400,
        max_response_bytes: int = 1_048_576,
    ) -> None:
        if ttl_seconds < 1 or max_response_bytes < 1:
            raise ValueError("idempotency TTL and response size must be positive")
        self.client = client
        self.key_prefix = key_prefix
        self.ttl_seconds = ttl_seconds
        self.max_response_bytes = max_response_bytes

    @classmethod
    def from_settings(cls) -> RedisIdempotencyStore:
        client = redis.Redis.from_url(
            settings.REDIS_IDEMPOTENCY_URL,
            socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
            socket_connect_timeout=settings.REDIS_SOCKET_TIMEOUT,
            decode_responses=True,
        )
        return cls(
            client,
            ttl_seconds=settings.IDEMPOTENCY_TTL_SECONDS,
            max_response_bytes=settings.IDEMPOTENCY_MAX_RESPONSE_BYTES,
        )

    def _key(self, *, actor_id: str, method: str, route: str, key: str) -> str:
        scope = "\0".join((actor_id, method.upper(), route, key))
        digest = hashlib.sha256(scope.encode("utf-8")).hexdigest()
        return f"{self.key_prefix}:{digest}"

    @staticmethod
    def _validate_key(key: str) -> None:
        if not key or len(key) > 255 or key.strip() != key or not key.isprintable():
            raise ValueError(
                "idempotency key must be printable, trimmed, and at most 255 characters"
            )

    def begin(
        self,
        *,
        actor_id: str,
        method: str,
        route: str,
        key: str,
        fingerprint: str,
    ) -> IdempotencyDecision:
        if not actor_id or not route or not method:
            raise ValueError("actor_id, method, and route are required")
        self._validate_key(key)
        if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
            raise ValueError("fingerprint must be a lowercase SHA-256 hex digest")

        redis_key = self._key(actor_id=actor_id, method=method, route=route, key=key)
        owner_token = secrets.token_urlsafe(24)
        record = {
            "version": 1,
            "state": "in_progress",
            "fingerprint": fingerprint,
            "owner_token": owner_token,
        }
        encoded = json.dumps(record, separators=(",", ":"))
        try:
            created = self.client.set(redis_key, encoded, nx=True, ex=self.ttl_seconds)
            if created:
                return IdempotencyDecision(
                    "execute", reservation=IdempotencyReservation(redis_key, owner_token)
                )
            existing = self.client.get(redis_key)
        except redis.exceptions.RedisError as exc:
            raise IdempotencyUnavailable("idempotency Redis is unavailable") from exc

        if not existing:
            raise IdempotencyUnavailable("idempotency reservation disappeared unexpectedly")
        try:
            stored = json.loads(existing)
        except (TypeError, json.JSONDecodeError) as exc:
            raise IdempotencyUnavailable("idempotency record is invalid") from exc
        if stored.get("version") != 1 or stored.get("fingerprint") != fingerprint:
            raise IdempotencyConflict("idempotency key was already used for a different request")
        if stored.get("state") == "in_progress":
            return IdempotencyDecision("in_progress")
        if stored.get("state") != "completed":
            raise IdempotencyUnavailable("idempotency record has an unknown state")

        try:
            body = base64.b64decode(stored["body_b64"], validate=True)
            response = StoredResponse(
                status_code=int(stored["status_code"]),
                body=body,
                content_type=str(stored.get("content_type", "application/json")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise IdempotencyUnavailable("completed idempotency response is invalid") from exc
        return IdempotencyDecision("replay", response=response)

    def complete(self, reservation: IdempotencyReservation, response: StoredResponse) -> None:
        if len(response.body) > self.max_response_bytes:
            raise ValueError("idempotency response exceeds configured size limit")
        encoded_body = base64.b64encode(response.body).decode("ascii")
        try:
            result = int(
                self.client.eval(
                    _COMPLETE_SCRIPT,
                    1,
                    reservation.redis_key,
                    reservation.owner_token,
                    response.status_code,
                    response.content_type,
                    encoded_body,
                    self.ttl_seconds,
                )
            )
        except redis.exceptions.RedisError as exc:
            raise IdempotencyUnavailable("idempotency Redis is unavailable") from exc
        if result == 0:
            raise IdempotencyOwnershipError("idempotency reservation is owned by another request")
        if result != 1:
            raise IdempotencyUnavailable("idempotency reservation no longer exists")
