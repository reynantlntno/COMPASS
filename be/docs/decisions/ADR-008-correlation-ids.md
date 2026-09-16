# ADR-008: Correlate requests and future tasks

## Context

Requests will cross Caddy, Gunicorn, Django, Redis, and Celery. Operators need one identifier to
follow a request without putting credentials, tokens, bodies, or query strings in logs.

## Decision

Generate a UUID for every request. Reuse a supplied `X-Request-ID` only when it is a canonical
UUID; replace invalid input. Return it in every response and store it in a context variable for
structured logs. The Celery task base propagates the ID in task headers and restores it in worker
context.

## Consequences

Logs are searchable by request ID and task logs can retain the originating context. Client-supplied
IDs are constrained to a predictable format, and task arguments remain outside the logging layer.
