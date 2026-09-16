# ADR-004: Redis-backed Celery with one worker and Beat boundary

## Context

The system needs asynchronous work, delayed scheduling, transient counters, and cache state. The
requested foundation names Redis, Celery, workers, and Beat, but does not define specialized
queues or domain jobs.

## Decision

Use Redis as the Celery broker and result backend, with separate logical Redis databases for
broker, cache, rate-limit, and idempotency concerns. Run the same application image as web,
worker, and one Beat service with command-only differences. Keep the Beat schedule empty until a
real recurring job exists; retain one harmless diagnostic task for smoke testing.

## Consequences

Redis state is transient infrastructure, not authoritative business data. Task bodies must be
safe to retry or deduplicate when domain tasks are added. Strict delivery guarantees may later
justify a broker review; Redis is the deliberate starting point here.
