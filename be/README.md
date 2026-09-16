# COMPASS backend foundation

This directory contains the backend foundation for COMPASS plus Accounts / Identity, Audit Trail,
Authentication / Account Security, and self-activity projections. It intentionally stops before business
workflows: configuration, health, error handling, request correlation, rate-limit and idempotency
primitives, external-service adapters, account identity, capability policy, server-managed
authentication, and local/live-staging container wiring are included. Organizational scope and
service domains remain deferred.

## Baseline

- Python 3.13, managed with `uv`
- Django 6.1.1 with Django Ninja 1.7.0
- PostgreSQL 17.11 as the source of truth
- Redis 8.10.1 for broker/cache/transient infrastructure
- Celery 5.6.3 with Redis broker and one Beat service
- S3-compatible object storage through `django-storages` and boto3
- Gunicorn behind Caddy 2.11.4
- MinIO and Mailpit only in the local Compose profile
- Custom UUID-based account identity with email as its canonical identifier
- Explicit roles, designations, capabilities, and account-level capability overrides
- Private, normalized WebP profile photos through object storage
- Synchronous, append-only-by-application Audit Trail events in PostgreSQL
- Server-managed opaque authentication sessions with revocation and session inspection
- HttpOnly cookie authentication with Django CSRF protection
- Explicit PyOTP TOTP MFA, hashed recovery codes, trusted sessions, and recent-MFA state
- Internal email OTP challenge storage and Celery delivery boundary
- Curated self-only My Activity and Security Activity projections over AuditEvent

The dependency lockfile is committed with this foundation. The chosen Python version is 3.13
because the current Celery 5.6 support matrix lists CPython 3.9 through 3.13; host Python 3.14
can still be used to install `uv`, but the project runtime remains pinned to 3.13.

## Local-staging setup

Prerequisites: Podman, `podman-compose` (or a compatible `podman compose` provider), and `uv`.

```sh
cd /Users/reynantlntno/Projects/COMPASS/be
cp .env.example .env
uv python install 3.13
uv sync
podman compose --profile local build web
podman compose --profile local up -d
podman compose --profile local run --rm web python manage.py migrate
podman compose --profile local run --rm web python manage.py check
```

Migrations are explicit and are not hidden in an entrypoint or run by every web/worker/Beat
container. This avoids multiple containers racing to mutate the schema.

Useful endpoints:

```sh
curl -i http://localhost:8080/api/v1/health/live
curl -i http://localhost:8080/api/v1/health/ready
```

When `API_DOCS_ENABLED=true`, the versioned OpenAPI UI is at
`http://localhost:8080/api/v1/docs`. Mailpit is at `http://localhost:8025`; MinIO's API is on
port 9000 and its local console is on port 9001. Both are bound to loopback by default.

## Authentication and account security development

Authentication uses a random, server-managed opaque credential in the configurable
`AUTH_SESSION_COOKIE_NAME` cookie. The credential is `HttpOnly`, scoped to `AUTH_SESSION_COOKIE_PATH`,
and resolves to an `AuthSession` row whose PostgreSQL value is only a SHA-256 digest. Trusted
browser credentials and short-lived MFA login challenges follow the same digest-only pattern; no
credential is returned in JSON or stored in browser `localStorage`. Local-staging defaults to
`SameSite=Lax` and non-Secure cookies so the loopback HTTP proxy remains usable. Live-staging
requires `AUTH_COOKIE_SECURE=true` and an explicit deployment-appropriate SameSite/origin policy.

The copied `.env` needs a deployment-local `AUTH_TOTP_ENCRYPTION_KEY` before TOTP enrollment or
verification can run. Generate a Fernet key without putting it in the repository:

```sh
uv run python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

The browser first calls `GET /api/v1/auth/csrf`, then sends the returned token in
`X-CSRFToken` on state-changing requests. The session, trusted-session, and MFA challenge cookies
remain `HttpOnly`; only Django's CSRF cookie is readable by the SPA pattern. Useful auth routes are:

```text
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/session
GET  /api/v1/auth/sessions
POST /api/v1/auth/mfa/totp/setup
POST /api/v1/auth/mfa/totp/confirm
POST /api/v1/auth/mfa/totp/verify
POST /api/v1/auth/mfa/totp/disable
GET  /api/v1/me/activity?page=1&page_size=20
GET  /api/v1/me/security-activity?page=1&page_size=20
```

TOTP setup is a two-step operation: call `setup`, scan the returned provisioning URI, then call
`confirm`. Confirmation returns recovery codes once; PostgreSQL stores only the encrypted TOTP
secret and one-way recovery-code hashes. The current default does not require MFA for every role,
but an enrolled factor causes MFA at the next password login. Role-specific mandatory MFA can be
configured with `AUTH_MFA_REQUIRED_ROLE_CODES`; the setting remains separate from capabilities.

Email OTP is intentionally an internal foundation rather than a public recovery API. Its challenge
row stores only a hash, and issuance/resend delivery is queued through the existing Celery + SMTP
adapter. For local delivery checks, inspect Mailpit after exercising the internal service boundary;
password-reset and full account-recovery workflows are deferred. Trusted sessions are listed and
revoked through the authenticated `/api/v1/auth/trusted-sessions` routes, while future account and
security-reset services can call the explicit revocation primitives directly. MFA disable and
recovery-code regeneration require recent MFA; `AUTH_RECENT_MFA_WINDOW_SECONDS` controls the
window.

The `minio-init` service creates the configured bucket and explicitly keeps it private. Re-run
it after the MinIO service is available if the bucket needs to be bootstrapped again:

```sh
podman compose --profile local run --rm minio-init
```

Synchronize the version-controlled identity policy before creating an initial IT administrator:

```sh
uv run python manage.py sync_identity_policy
uv run python manage.py create_it_admin \
  --email it-admin@example.edu \
  --first-name IT \
  --last-name Administrator
```

The bootstrap command prompts for the password and never accepts it as a command-line argument.
Use `--password-stdin` for a controlled non-interactive deployment. Re-running policy sync is
safe; it updates known definitions, adds missing baseline grants, and retains unknown database
rows. `create_it_admin` refuses an existing account unless `--idempotent` is explicitly supplied.

## Audit Trail development

The Audit Trail records meaningful business and security actions for accountability. It is separate
from structured operational logs, HTTP access logs, and domain records. There is no audit read API
yet; future domains must record sensitive reads explicitly at their service/use-case boundary.

Record an event directly and keep a successful state change and its `SUCCESS` event in the same
`transaction.atomic()` block:

```python
from django.db import transaction

from compass.audit import record
from compass.audit.context import AuditContext
from compass.audit.models import AuditEvent

with transaction.atomic():
    user.save(update_fields=["first_name", "updated_at"])
    record(
        context=AuditContext.from_request(request),
        action="accounts.updated",
        outcome=AuditEvent.Outcome.SUCCESS,
        target_type="accounts.user",
        target_id=user.pk,
        metadata={"changed_fields": ["first_name"]},
    )
```

Use `AuditContext.system()` for management commands and internal processes, and
`AuditContext.anonymous()` for meaningful unauthenticated security events. Metadata must be a
small, explicit JSON object; never include passwords, hashes, tokens, credentials, request or
response bodies, or confidential counseling content. Audit events cannot be edited or deleted
through normal application ORM paths. Retention, tamper-proof storage, and capability-scoped
audit viewing are deferred to later policy and domain work.

## My Activity and Security Activity

The two authenticated `/api/v1/me/*` endpoints are presentation projections over the existing
AuditEvent table; they do not create an ActivityLog table, copy events, or mutate audit rows. Each
feed uses an explicit action/presenter allowlist, so new audit actions remain hidden until a safe
human-readable presentation is intentionally registered. My Activity is the broader account feed;
Security Activity includes selected authentication history such as successful/known-account failed
sign-ins, session creation/revocation, MFA enrollment, recovery-code use, and trusted-browser
changes. Internal policy synchronization, email OTP operations, raw MFA verification attempts, and
unknown actions remain hidden.

Responses contain only `id`, stable `type`, neutral `title`/`description`, `occurred_at`, and
bounded pagination fields. Raw audit metadata, actor/target internals, request IDs, IP addresses,
user-agent values, credentials, and security tokens are excluded. Pagination is newest-first with
`page_size` limited to 50, and the endpoints never accept a user ID or audit search filter.

## Live-staging outline

Create a deployment-only `.env` from the same settings contract and set:

- `APP_ENV=live-staging`, `DEBUG=false`, a generated `SECRET_KEY`, and explicit `ALLOWED_HOSTS`;
- PostgreSQL credentials/host and Redis URLs that are reachable only on the private network;
- `S3_ENDPOINT_URL` and credentials for the approved external S3-compatible service;
- real SMTP host/credentials; do not use Mailpit;
- `TURNSTILE_ENABLED=true`, the server-only Turnstile secret, and expected hostname/action values;
- a valid `AUTH_TOTP_ENCRYPTION_KEY` in deployment secret storage, `AUTH_COOKIE_SECURE=true`,
  and explicit auth cookie/origin policy;
- `CADDY_ADDRESS` and `CADDY_HEALTH_HOST` to the staging hostname,
  `PROXY_BIND_ADDRESS=0.0.0.0`, and ports 80/443.

Start only the non-local services on the droplet:

```sh
podman compose up -d
podman compose run --rm web python manage.py migrate
podman compose run --rm web python manage.py check --deploy
```

The same backend image is used by `web`, `worker`, and `beat`; only the command differs. Keep
exactly one Beat service per environment. Expose only Caddy publicly, keep PostgreSQL/Redis
private, and allowlist Cloudflare's published IP ranges at the droplet firewall/security layer
before relying on forwarded client-IP headers. The current Caddyfile includes the Cloudflare
ranges and enables strict trusted-proxy parsing; review/update those ranges as part of deployment
maintenance.

## Quality commands

```sh
uv lock
uv sync
uv run ruff format --check .
uv run ruff check .
uv run pytest
uv run pytest tests/test_audit.py
uv run python manage.py check
uv run python manage.py makemigrations --check --dry-run
```

The test suite uses mocked dependency boundaries for Turnstile, Redis primitives, object storage,
and the readiness database probe. It does not call external services. Add integration tests against
the Compose services when deployment automation is introduced.

## API and infrastructure conventions

- `GET /api/v1/health/live` is process-only liveness.
- `GET /api/v1/health/ready` checks PostgreSQL with `SELECT 1` and returns 503 when unavailable.
- Every response receives a valid `X-Request-ID`; a supplied ID is reused only when it is a
  canonical UUID. Invalid values are replaced. Logs contain controlled JSON fields and never
  include request bodies, query strings, tokens, or credentials.
- API/Django errors share a stable `{ "error": { "code", "message", "request_id" } }` envelope.
  Remote responses do not expose tracebacks.
- Authentication failures are externally generic; opaque session and trusted-session credentials,
  passwords, MFA codes, OTP values, and Turnstile tokens are not placed in API JSON or audit
  metadata. Cookie-authenticated state changes require Django CSRF validation.
- Redis rate limiting uses an atomic Lua `INCR`/`EXPIRE` operation, but no endpoint policy is
  invented here. Turnstile verification is a separate server-side adapter and is not a rate limit.
- Idempotency is a reusable Redis reservation/replay boundary keyed by actor + method + route +
  idempotency key and compared by request fingerprint. It is not a substitute for database
  uniqueness constraints and is not attached to an endpoint yet.
- Storage and email calls go through app-facing adapters. Durable uploads are not written to the
  container filesystem.
- Audit events are synchronous PostgreSQL writes through one explicit service. They carry the
  existing request ID, trusted client IP, bounded user-agent summary, actor, outcome, target, and
  small deliberate metadata; they do not replace operational logging.

## Decisions

See [`docs/decisions/`](docs/decisions/) for the foundation ADRs, including the deliberate choices
to use Django Ninja, omit admin, keep PostgreSQL authoritative, separate Redis concerns, abstract
S3-compatible storage, separate capability from future scope, use one environment-driven settings
module, propagate correlation IDs, define idempotency semantics, establish explicit account
identity policy, keep Audit Trail recording explicit and separate from operational logs, and use
server-managed cookie sessions for authentication.

## Known verification gaps

The Compose files are designed for Podman; image pulls, Caddy validation, and a full multi-container
smoke test require a running Podman machine and are listed as deployment checks. MinIO is
appropriate for local S3 compatibility testing; live-staging should use the approved external
provider after its lifecycle, retention, backup, and TLS policy are confirmed. The email OTP
foundation has no user-facing recovery endpoint yet; password reset, account administration,
organization/scope, Activity Log, and Audit read APIs remain separate follow-up slices.
