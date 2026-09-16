# ADR-006: Keep capability separate from organizational scope

## Context

The future product needs roles/capabilities and scope rules, but organizational units, ownership
semantics, and resource boundaries are not part of the Accounts / Identity foundation.

## Decision

The Accounts / Identity app owns a small, explicit capability catalog and resolver. Capability
codes describe what an actor may do, without embedding a campus, college, department, or other
population in the code. Future authorization must be evaluated at the route/service boundary with
both the capability and the resource scope explicit. Django Groups, generated model permissions,
and `is_superuser` are not COMPASS business authorization.

## Consequences

The foundation has capability behavior but no organizational scope behavior. Domain design must
document actor identity, capability names, resource scope, denial behavior, and audit requirements
before adding routes.
