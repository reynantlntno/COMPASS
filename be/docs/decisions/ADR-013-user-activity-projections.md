# ADR-013: Curated self-activity projections over the Audit Trail

## Context

COMPASS needs readable activity history for an authenticated account without turning the
account-facing API into a general audit viewer. `audit.AuditEvent` already persists attributable
business and security evidence, including authentication events and explicit targets. Creating a
second activity table would duplicate history, complicate retention, and risk exposing audit
details that are appropriate only for authorized investigation.

## Decision

Keep `audit.AuditEvent` as the only persisted source of truth. `GET /api/v1/me/activity` and
`GET /api/v1/me/security-activity` synchronously query selected events and transform them through
explicit presenter registries. My Activity is the broader curated account feed; Security Activity
is the narrower account-security feed. Some security items intentionally overlap because the two
feeds have different user-facing purposes.

Each presenter explicitly declares its stable public type, neutral copy, allowed outcome, actor
scope, and target ownership rule. A new or removed audit action is not visible by default. Current
target checks allow self-actor events only when their account/session/MFA target belongs to the
current user, and allow the existing system-generated `account.created` event only when it targets
the current account. This keeps the selection architecture ready for future explicit
actor-versus-account target policies without introducing broad target matching.

The response contains only an audit UUID, stable type, title, description, and timestamp. Raw
metadata, target fields, actor identity, request IDs, IP addresses, user-agent values, credentials,
and security tokens are never returned. The endpoints authenticate through the existing opaque
COMPASS session and accept no user selector or audit filters. Page/page-size pagination is bounded
and ordered newest-first by `(occurred_at, id)`.

## Consequences

There is no `ActivityLog`, `ActivityEvent`, `UserActivity`, or `SecurityActivity` model, no feed
materialization job, no Redis feed cache, and no AuditEvent mutation for read state. The endpoints
are self-only and do not require a capability because viewing one's own safe account activity is an
inherent authenticated-account ability. A general Audit Viewer, audit search/export, notifications,
read/unread state, domain history, and future account-management projections remain deferred.
