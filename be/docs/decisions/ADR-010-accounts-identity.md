# ADR-010: Establish explicit COMPASS account identity and policy

## Context

Future COMPASS domains will reference accounts. The default Django user includes username,
superuser, staff, groups, and generated model-permission assumptions that do not match the
product's intended authorization direction. Account identity also needs to remain separate from
future student/counselor profiles and organizational scope.

## Decision

Use `accounts.User`, based on `AbstractBaseUser`, with a UUID primary key and email as the
canonical identity field. COMPASS treats the full email string as case-insensitive, so the account
manager and model trim and lowercase it without changing plus-addressing, dots, or other valid
address structure. PostgreSQL independently enforces case-insensitive uniqueness with a
`Lower(email)` unique constraint. The model has one
required primary `Role`; `Designation` is a separate many-to-many appointment represented by
`UserDesignation`.

COMPASS capabilities are explicit dotted codes. Role and designation grants are represented by
`RoleCapability` and `DesignationCapability`; `UserCapabilityOverride` stores exceptional,
reasoned account-level grants or revocations. The effective resolver combines role and designation
grants with active overrides and subtracts revocations last. Canonical definitions and baseline
grants live in version-controlled Python policy and are synchronized idempotently by
`sync_identity_policy`. Initial IT administrator creation is a separate `create_it_admin` command.

The app does not use `PermissionsMixin`, Django Groups, generated model permissions, `is_staff`, or
`is_superuser` for COMPASS authorization. Django Admin and unaudited privilege-management HTTP
endpoints remain disabled.

Profile photos are optional visual identity cues. Image contents are validated and decoded with
Pillow, normalized to metadata-free WebP, and stored as private S3-compatible objects through the
existing storage abstraction. PostgreSQL stores only the object key and update timestamp. New
objects are written before the account reference changes; old-object cleanup is scheduled after a
successful database commit.

## Consequences

Future foreign keys can safely reference `settings.AUTH_USER_MODEL` before business domains are
introduced. Identity, operational role, institutional designation, capability, and future scope
remain distinct and readable. Authentication flows, audit events, organizational scope, and
profile-domain models require separate decisions and are intentionally not implemented here.
