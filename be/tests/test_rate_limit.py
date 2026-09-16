import redis
from django.test import RequestFactory, override_settings

from compass.common.rate_limit import RateLimitPolicy, RedisRateLimiter, client_ip


class FakeRedis:
    def __init__(self, counts):
        self.counts = iter(counts)
        self.calls = []

    def eval(self, script, number_of_keys, key, window_seconds):
        self.calls.append((script, number_of_keys, key, window_seconds))
        return next(self.counts)

    def ttl(self, key):
        return 17


def test_rate_limiter_uses_atomic_increment_and_expiry_script():
    client = FakeRedis([1, 3])
    limiter = RedisRateLimiter(client)
    policy = RateLimitPolicy("login", limit=2, window_seconds=60)

    allowed = limiter.consume(policy, "actor:123")
    blocked = limiter.consume(policy, "actor:123")

    assert allowed.allowed is True
    assert allowed.remaining == 1
    assert blocked.allowed is False
    assert "INCR" in client.calls[0][0]
    assert "EXPIRE" in client.calls[0][0]


def test_client_ip_only_honors_forwarded_headers_from_trusted_proxy():
    factory = RequestFactory()
    forwarded = factory.get(
        "/",
        REMOTE_ADDR="10.0.0.5",
        HTTP_CF_CONNECTING_IP="203.0.113.10",
    )
    untrusted = factory.get(
        "/",
        REMOTE_ADDR="203.0.113.11",
        HTTP_CF_CONNECTING_IP="198.51.100.8",
    )

    with override_settings(TRUSTED_PROXY_CIDRS=["10.0.0.0/8"]):
        assert client_ip(forwarded) == "203.0.113.10"
        assert client_ip(untrusted) == "203.0.113.11"


def test_rate_limiter_fails_closed_by_default_and_can_be_configured_open():
    class BrokenRedis:
        def eval(self, *args):
            raise redis.exceptions.ConnectionError("unavailable")

    policy = RateLimitPolicy("login", limit=2, window_seconds=60)
    limiter = RedisRateLimiter(BrokenRedis())

    with override_settings(RATE_LIMITER_FAIL_OPEN=False):
        try:
            limiter.consume_with_failure_policy(policy, "actor:123")
        except RuntimeError as exc:
            assert "unavailable" in str(exc)
        else:  # pragma: no cover - assertion branch
            raise AssertionError("rate limiter should fail closed")

    with override_settings(RATE_LIMITER_FAIL_OPEN=True):
        result = limiter.consume_with_failure_policy(policy, "actor:123")

    assert result.allowed is True
    assert result.remaining == policy.limit
