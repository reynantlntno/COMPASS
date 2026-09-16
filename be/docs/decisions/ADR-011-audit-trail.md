# ADR-011: Explicit PostgreSQL Audit Trail

## Context

COMPASS needs an attributable history of meaningful business and security actions for
accountability and investigation. Existing structured logs serve operational diagnostics and HTTP
request observability; they are not a durable business audit record. Audit events must not become a
second copy of sensitive domain data.

## Decision

Use a small `audit.AuditEvent` model stored synchronously in PostgreSQL. Business services record
events explicitly through one `record_event()` service, normally inside the same `transaction.atomic()`
block as the successful state change. `DENIED` and relevant `FAILED` events can be recorded
explicitly in their own transaction.

An event has a `USER`, `SYSTEM`, or `ANONYMOUS` actor, with a protected optional relationship to a
COMPASS user. Cross-domain targets use paired `target_type` and `target_id` values instead of a
`GenericForeignKey`. Action codes are lowercase dotted identifiers. Metadata is a small, explicit
JSON object and call sites must keep secrets and confidential domain content out of it.

HTTP request contexts reuse the existing request/correlation ID and trusted client-IP resolver;
they do not parse forwarded headers independently. User agents are bounded summaries. Future
sensitive-record reads are audited explicitly by their owning domain, not by generic middleware.

Application model/queryset boundaries reject normal edits, updates, and deletes, so the trail is
append-only by application design. No Django signals, Celery transport, audit read API, retention
job, cryptographic hash chain, or database tamper-proofing trigger is introduced here.

## Consequences

Audit records remain transactionally aligned with successful state changes and are queryable by
time, action, actor, target, and request ID. The audit table contains accountability metadata but
is not itself a complete tamper-proof ledger. Actor accounts should be disabled rather than deleted;
institutional retention, archival, privacy/anonymization, and capability-scoped audit viewing are
deferred until their policies are approved.
