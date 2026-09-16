# ADR-017: Organization and default responsibility scope

## Context

COMPASS needs enough institutional structure to route students to the people normally responsible for them without turning organizational affiliation into permanent authorization. Roles, designations, capabilities, organizational responsibility, and future resource/case assignment are separate concepts.

## Decision

Model the current hierarchy explicitly as `Campus -> College`. Do not add a generic organizational tree. `StudentAffiliation` stores one student's current College for COMPASS routing only. A College has at most one `CounselorResponsibility`, while a Counselor may cover several Colleges. `StaffSupervision` gives one Guidance Services Staff account at most one supervising Counselor; staff scope is resolved dynamically from the active supervisor and does not copy capabilities, designations, MFA state, or future case-specific exceptions.

An active user with role `COUNSELOR` and designation `HEAD_GUIDANCE_COUNSELOR` has institution-wide default responsibility over active Colleges whose Campus is active. No per-College rows are materialized for the Head. Default student routing is Student -> current College -> active default Counselor -> exactly one active Head fallback. Zero Heads is unresolved; multiple valid Heads is an explicit ambiguous configuration and no arbitrary row is selected.

Organizational scope is default responsibility/routing context, not a hard access wall. A later service/appointment slice may allow a student to choose an eligible Counselor outside the student's College. A later case/resource assignment may authorize a Counselor for a specific out-of-scope record. Guidance Services Staff will not automatically inherit those case-specific exceptions.

The source-controlled identity policy adds `organization.view` and `organization.manage`. IT Admin receives both; Counselor, Guidance Services Staff, and Student receive view; the Head designation grants manage. Capability overrides remain authoritative, so REVOKE wins. Revoking management capability does not erase Head responsibility semantics.

Organization mutations use transactions, ordinary row locking, recent-MFA step-up, and synchronous Audit Trail events. Campuses and Colleges are enabled/disabled rather than hard-deleted. A Campus cannot be disabled while it has active Colleges. A College cannot be disabled while current student affiliations or default counselor responsibilities remain. Inactive users keep relationship rows, but resolvers treat them as operationally unavailable.

Account Management calls an Organization-owned role-transition validator before changing a primary role. Role changes that would leave a counselor responsibility, staff supervision, or student affiliation semantically invalid are rejected with a conflict; no signal or silent cleanup is used.

## Consequences

The model stays deliberately small and explainable. Accounts remains identity and gains no campus, college, or supervisor columns. Future Department/Program structure, preferred counselor persistence, service eligibility, and case/resource authorization are deferred until concrete requirements exist.
