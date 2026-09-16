import json

import pytest

from compass.common.idempotency import (
    IdempotencyConflict,
    RedisIdempotencyStore,
    StoredResponse,
    request_fingerprint,
)


class FakeRedis:
    def __init__(self):
        self.records = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.records:
            return False
        self.records[key] = value
        return True

    def get(self, key):
        return self.records.get(key)

    def eval(
        self, script, number_of_keys, key, owner_token, status_code, content_type, body_b64, ttl
    ):
        record = json.loads(self.records[key])
        if record["owner_token"] != owner_token:
            return 0
        record.update(
            {
                "state": "completed",
                "status_code": int(status_code),
                "content_type": content_type,
                "body_b64": body_b64,
            }
        )
        self.records[key] = json.dumps(record)
        return 1


def _fingerprint(body=b'{"value":1}'):
    return request_fingerprint(method="POST", route="/api/v1/example", query_string="", body=body)


def test_idempotency_reserves_replays_and_rejects_different_requests():
    store = RedisIdempotencyStore(FakeRedis(), ttl_seconds=60)
    fingerprint = _fingerprint()

    first = store.begin(
        actor_id="user:1",
        method="POST",
        route="/api/v1/example",
        key="request-1",
        fingerprint=fingerprint,
    )
    in_progress = store.begin(
        actor_id="user:1",
        method="POST",
        route="/api/v1/example",
        key="request-1",
        fingerprint=fingerprint,
    )
    assert first.outcome == "execute"
    assert in_progress.outcome == "in_progress"

    stored = StoredResponse(201, b'{"id":"abc"}')
    store.complete(first.reservation, stored)
    replay = store.begin(
        actor_id="user:1",
        method="POST",
        route="/api/v1/example",
        key="request-1",
        fingerprint=fingerprint,
    )
    assert replay.outcome == "replay"
    assert replay.response == stored

    with pytest.raises(IdempotencyConflict):
        store.begin(
            actor_id="user:1",
            method="POST",
            route="/api/v1/example",
            key="request-1",
            fingerprint=_fingerprint(b'{"value":2}'),
        )
