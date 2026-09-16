# ADR-003: PostgreSQL is the source of truth

## Context

COMPASS requires relational integrity, migrations, and durable application state. SQLite would
hide production-specific behavior and is not an accepted staging baseline.

## Decision

Use PostgreSQL 17 for local-staging and live-staging. Django is configured with psycopg, persistent
Compose storage, connection health checks, and explicit migrations. Redis and object storage are
not substitutes for relational truth.

## Consequences

Local development needs PostgreSQL through the Compose stack or an equivalent server. PostgreSQL
17 is selected over 18 for the initial baseline because it is a current supported major release
and avoids introducing a newer data-directory/image transition before the deployment path is
validated.
