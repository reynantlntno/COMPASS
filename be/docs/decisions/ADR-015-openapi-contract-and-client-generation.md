# ADR-015: Versioned OpenAPI contract for frontend client generation

## Context

COMPASS backend and frontend work will proceed in parallel. Django Ninja already generates the
v1 API schema, but default operation IDs, inconsistent tags, and success-only response
documentation would make generated clients sensitive to backend implementation details.

## Decision

Treat the OpenAPI 3.1 document for `/api/v1/` as a versioned development contract. Every public
operation has an explicit camelCase `operationId`: `health<Action>`, `auth<Action>`,
`me<Action>`, or `accounts<Action>`. Tags are the stable bounded domains `health`, `auth`,
`activity`, and `accounts`; they do not represent user roles.

Use shared `APIErrorResponse`, `APIErrorDetail`, and `ValidationIssue` schemas for the existing
central JSON error envelope, and document realistic operation-specific status codes. Keep the
existing `OpaqueSessionAuth` API-key-cookie representation. The auth credential remains an
HttpOnly opaque cookie; Django CSRF remains a separate browser/header mechanism and is not
represented as a bearer credential.

Generate the schema from the actual Ninja API with the installed Django management command:
`export_openapi`. The canonical, sorted, newline-terminated artifact is
`contracts/openapi.json`; `export_openapi --check` compares parsed schema content without
depending on HTTP docs exposure. The artifact must be updated in the same change as an
intentional public contract change.

The future frontend may use Orval with Fetch and TanStack Query in `tags-split` mode. Orval is
frontend tooling only and is not a backend runtime dependency. Generated frontend code and its
configuration are owned by `fe/`. The preferred browser architecture uses same-origin relative
`/api/` requests through a frontend proxy or ingress. Browser clients must preserve cookie
credentials and CSRF behavior, never read/store auth credentials, and a future SSR adapter must
forward request-scoped cookies explicitly rather than weakening cookie security.

Backend implementation details—including Python function names, service layout, and ORM queries—
may change freely. Paths, methods, operation IDs, parameters, schemas, status codes, enum values,
and security requirements require intentional contract review.

## Consequences

Frontend development can generate stable typed models, Fetch functions, and TanStack Query hooks
from a committed artifact while backend internals continue to evolve. Contract tests and the
export check provide a small CI gate, while Swagger remains environment-sensitive and optional
in live-staging. JWT, localStorage authentication, permissive CORS, API v2, and permanent
generated frontend source are not introduced.
