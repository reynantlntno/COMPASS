# ADR-006: Reserve capability and scope design for the domain contract

## Context

The future product needs roles/capabilities and likely scope rules, but the foundation brief does
not define tenants, organizations, ownership semantics, or resource boundaries.

## Decision

Do not create placeholder roles, capability catalogs, permission tables, or generic authorization
shortcuts. Future authorization must be evaluated at the route/service boundary with both the
capability and the resource scope explicit.

## Consequences

The foundation has no business authorization behavior to accidentally treat as final. Domain
design must document actor identity, capability names, resource scope, denial behavior, and audit
requirements before adding routes.
