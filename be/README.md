# COMPASS backend foundation

This directory contains the backend foundation for COMPASS. It intentionally stops at
cross-cutting infrastructure: configuration, health, error handling, request correlation,
rate-limit and idempotency primitives, external-service adapters, and local/live-staging
container wiring. Business domains, workflows, admin UI, roles, and capability catalogs are
deferred until their contracts are agreed.

## Baseline

- Python 3.13, managed with `uv`
- Django 6.1.1 with Django Ninja 1.7.0
- PostgreSQL 17.11 as the source of truth
- Redis 8.10.1 for broker/cache/transient infrastructure
- Celery 5.6.3 with Redis broker and one Beat service
- S3-compatible object storage through `django-storages` and boto3
- Gunicorn behind Caddy 2.11.4
- MinIO and Mailpit only in the local Compose profile

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

The `minio-init` service creates the configured bucket and explicitly keeps it private. Re-run
it after the MinIO service is available if the bucket needs to be bootstrapped again:

```sh
podman compose --profile local run --rm minio-init
```

## Live-staging outline

Create a deployment-only `.env` from the same settings contract and set:

- `APP_ENV=live-staging`, `DEBUG=false`, a generated `SECRET_KEY`, and explicit `ALLOWED_HOSTS`;
- PostgreSQL credentials/host and Redis URLs that are reachable only on the private network;
- `S3_ENDPOINT_URL` and credentials for the approved external S3-compatible service;
- real SMTP host/credentials; do not use Mailpit;
- `TURNSTILE_ENABLED=true`, the server-only Turnstile secret, and expected hostname/action values;
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
- Redis rate limiting uses an atomic Lua `INCR`/`EXPIRE` operation, but no endpoint policy is
  invented here. Turnstile verification is a separate server-side adapter and is not a rate limit.
- Idempotency is a reusable Redis reservation/replay boundary keyed by actor + method + route +
  idempotency key and compared by request fingerprint. It is not a substitute for database
  uniqueness constraints and is not attached to an endpoint yet.
- Storage and email calls go through app-facing adapters. Durable uploads are not written to the
  container filesystem.

## Decisions

See [`docs/decisions/`](docs/decisions/) for the nine foundation ADRs, including the deliberate
choices to use Django Ninja, omit admin, keep PostgreSQL authoritative, separate Redis concerns,
abstract S3-compatible storage, reserve future capability/scope design, use one environment-driven
settings module, propagate correlation IDs, and define idempotency semantics before domain routes.

## Known verification gaps

The repository root currently has no Git metadata, so this foundation cannot report a branch or
commit. The Compose files are designed for Podman; image pulls, Caddy validation, and a full
multi-container smoke test require a running Podman machine and are listed as deployment checks.
MinIO is appropriate for local S3 compatibility testing; live-staging should use the approved
external provider after its lifecycle, retention, backup, and TLS policy are confirmed.
