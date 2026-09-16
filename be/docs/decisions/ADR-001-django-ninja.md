# ADR-001: Use Django Ninja for the HTTP API

## Context

COMPASS needs a typed, versioned JSON API while retaining Django's settings, middleware,
security, ORM, sessions, and management commands. Django REST Framework is not part of the
requested foundation.

## Decision

Use Django Ninja with one `NinjaAPI` object mounted at `/api/v1/`. Keep route registration
versioned and use response schemas for the public contract. Authentication and authorization
will be explicit at route boundaries when domain APIs exist.

## Consequences

OpenAPI and interactive docs are available behind an environment flag. The project owns a
central exception-handler layer so debug behavior cannot leak tracebacks to remote clients.
