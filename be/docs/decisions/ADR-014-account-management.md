# ADR-014: Purpose-built administrative Account Management

## Context

COMPASS needs a controlled way for authorized administrators to manage account identity and
account security without exposing Django Admin, generic CRUD, or unrestricted audit data. The
current `accounts.view` capability is intentionally granted to operational roles for future
scoped workflows, but Organization & Scope does not exist yet.

## Decision

Implement explicit Django Ninja Account Management routes backed by transactional services. Every
management endpoint currently requires the effective `accounts.manage` capability; `accounts.view`
does not grant access to the global account list or detail APIs. Authorization uses the canonical
capability resolver, never a role-name shortcut.

Account creation uses `UserManager` and canonical policy role codes. New accounts receive an
unusable password; administrator-selected passwords, password recovery, invitations, and other
onboarding flows remain deferred. Identity fields, enable/disable, primary role, canonical
designation assignments, and account-level capability overrides each have explicit operations.
Role, designation, and capability definitions and their baseline grants remain version-controlled
policy and are not HTTP-managed.

All Account Management writes require the existing recent-MFA assertion. Email changes revoke
authentication and trusted sessions, invalidate login challenges and relevant old-identity email
security/recovery challenges, and preserve TOTP. Disable, authority changes, and MFA reset use the
existing authentication revocation primitives. Administrative MFA reset has its own low-level MFA
state-reset primitive, removes pending enrollment, invalidates recovery codes, and never returns
MFA material. TOTP is not reset for ordinary authority changes.

Authority-changing operations serialize on the canonical `accounts.manage` capability row, lock
the actor and target account rows, and verify that at least one active account still has effective
`accounts.manage`. This is a small PostgreSQL row-lock coordination point rather than a custom
distributed lock. Self-target restrictions prevent administrators from disabling themselves,
removing their own management authority, editing their own capability overrides, or using the
administrative MFA/session reset operations on themselves. Normal identity-field updates may
target the actor.

Successful mutations and their summary audit events commit in the same transaction. Session and
trusted-session revocations continue to emit the existing authentication audit actions. Only
safe account events are explicitly registered with the self-activity projections; capability
override internals are not exposed there. No account deletion, manual lock state, generic audit
viewer, or Organization & Scope model is introduced.

## Consequences

Account managers can perform the required identity, authority, status, and security operations
through a traceable API while preserving historical rows and credential boundaries. Global account
visibility remains intentionally restricted until scoped authorization exists. Future onboarding,
organizational responsibility, resource assignment, and audit investigation features require their
own policy decisions.
