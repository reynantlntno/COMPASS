# ADR-009: Define idempotency at the infrastructure boundary

## Context

Future state-changing API calls may be retried by clients or proxies. An idempotency key is not a
database uniqueness constraint and must not silently merge different request bodies.

## Decision

Provide a Redis reservation/replay store scoped by actor identity, HTTP method, route, and key.
The request fingerprint includes method, route, query string, and body. The first request reserves
the key; the same fingerprint replays a stored response; a different fingerprint is a conflict;
an active reservation is reported as in progress. Completion is owner-checked atomically and has
a bounded response size/TTL. The boundary is not attached to any endpoint until a domain defines
actor and response semantics.

## Consequences

The mechanism is reusable and clear about failure states, but it cannot replace database
constraints or make a non-idempotent domain side effect safe by itself. A domain endpoint must
choose when to reserve, how to handle in-progress requests, and how to persist its authoritative
state transactionally.
