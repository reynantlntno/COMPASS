# ADR-002: Do not enable Django admin in the foundation

## Context

The first milestone is backend infrastructure, not an operator console. Enabling admin would
expand the attack surface and imply an authorization model before roles and capabilities are
agreed.

## Decision

Do not install `django.contrib.admin`, expose an admin URL, or create an admin bypass. A future
operator surface must be designed as a separately authorized capability.

## Consequences

There is no `/admin/` route in this baseline. Operational work uses explicit management commands,
deployment tooling, and service health checks until an operator contract is approved.
