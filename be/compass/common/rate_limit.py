"""Reusable Redis-backed rate-limit primitives.

Policies are deliberately not attached to endpoints yet. Product-facing limits should be
chosen with the relevant domain owner instead of being guessed in the foundation layer.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from dataclasses import dataclass

import redis
from django.conf import settings

logger = logging.getLogger("compass.rate_limit")

_INCREMENT_WITH_EXPIRY = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""


class RateLimitUnavailable(RuntimeError):
    """Raised when the limiter cannot reach Redis."""


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    name: str
    limit: int
    window_seconds: int

    def __post_init__(self) -> None:
        if not self.name or self.limit < 1 or self.window_seconds < 1:
            raise ValueError(
                "rate-limit policy must have a name, positive limit, and positive window"
            )


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    allowed: bool
    count: int
    limit: int
    remaining: int
    retry_after_seconds: int


class RedisRateLimiter:
    def __init__(self, client, *, key_prefix: str = "compass:rate-limit") -> None:
        self.client = client
        self.key_prefix = key_prefix

    @classmethod
    def from_settings(cls) -> RedisRateLimiter:
        client = redis.Redis.from_url(
            settings.REDIS_RATE_LIMIT_URL,
            socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
            socket_connect_timeout=settings.REDIS_SOCKET_TIMEOUT,
            decode_responses=True,
        )
        return cls(client)

    def _key(self, policy: RateLimitPolicy, subject: str) -> str:
        digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()
        return f"{self.key_prefix}:{policy.name}:{digest}"

    def consume(self, policy: RateLimitPolicy, subject: str) -> RateLimitResult:
        if not subject:
            raise ValueError("rate-limit subject cannot be empty")
        key = self._key(policy, subject)
        try:
            count = int(self.client.eval(_INCREMENT_WITH_EXPIRY, 1, key, policy.window_seconds))
            ttl = int(self.client.ttl(key))
        except redis.exceptions.RedisError as exc:
            raise RateLimitUnavailable("rate limiter Redis is unavailable") from exc

        allowed = count <= policy.limit
        return RateLimitResult(
            allowed=allowed,
            count=count,
            limit=policy.limit,
            remaining=max(policy.limit - count, 0),
            retry_after_seconds=max(ttl, 0),
        )

    def consume_with_failure_policy(self, policy: RateLimitPolicy, subject: str) -> RateLimitResult:
        """Apply the configured availability policy; fail closed by default."""
        try:
            return self.consume(policy, subject)
        except RateLimitUnavailable:
            if not settings.RATE_LIMITER_FAIL_OPEN:
                raise
            logger.error(
                "rate limiter unavailable; allowing request by configured policy",
                extra={"event": "rate_limiter_fail_open"},
            )
            return RateLimitResult(
                allowed=True,
                count=0,
                limit=policy.limit,
                remaining=policy.limit,
                retry_after_seconds=0,
            )


def _trusted_proxy(remote_addr: str | None) -> bool:
    if not remote_addr:
        return False
    try:
        address = ipaddress.ip_address(remote_addr)
    except ValueError:
        return False
    for cidr in settings.TRUSTED_PROXY_CIDRS:
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            logger.warning("invalid trusted proxy CIDR", extra={"event": "invalid_proxy_cidr"})
    return False


def client_ip(request) -> str:
    """Return the peer address, honoring forwarded headers only from a trusted proxy."""
    remote_addr = request.META.get("REMOTE_ADDR")
    if _trusted_proxy(remote_addr):
        forwarded = request.META.get("HTTP_CF_CONNECTING_IP") or request.META.get("HTTP_X_REAL_IP")
        if forwarded:
            try:
                return str(ipaddress.ip_address(forwarded.strip()))
            except ValueError:
                pass
    return remote_addr or "unknown"
