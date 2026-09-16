# ADR-016: Self-service initial password setup and recovery

## Context

Account Management intentionally creates users with unusable passwords so administrators never
choose, receive, or know another user's password. COMPASS needs a single self-service flow for a
newly created account and for a user who has forgotten an existing password. The registered email
is the available recovery address, and the project already has a bounded, hash-only email OTP
foundation with Celery delivery.

## Decision

Use `POST /api/v1/auth/password/request` followed by
`POST /api/v1/auth/password/confirm` for both initial password setup and password recovery. Both
flows use `EmailOTPPurpose.RECOVERY`; no recovery-token model, JWT, invitation token, or temporary
session is introduced. The request response is intentionally uniform for eligible, disabled, and
unknown addresses. Active known accounts receive a dispatched OTP challenge; disabled and unknown
addresses receive an equivalent non-dispatched decoy challenge. A new request invalidates older
outstanding recovery challenges for the same account/email.

The confirm service locks the account and challenge rows in PostgreSQL, verifies the OTP through
the shared internal email-OTP primitive, validates the proposed password with Django's configured
password validators, calls `set_password()`, consumes the OTP, invalidates other recovery
challenges, revokes reusable authentication state, and records the successful password event in
one transaction. A valid OTP is not consumed when password policy validation fails, so the user
can correct a weak password without requesting another code. The result never creates an
authentication session; the user must complete normal password login and any configured MFA.

The password baseline uses Django's built-in similarity, minimum-length, common-password, and
numeric validators with a fifteen-character minimum. No composition rules, password history,
password expiry, or security questions are added. Exact current-password reuse is rejected after
the email challenge is proven. Password reset revokes all reusable sessions, trusted sessions,
login challenges, and other recovery challenges, but preserves the active TOTP factor and MFA
recovery codes. Email changes and administrative disablement remain defense-in-depth barriers to
using an old challenge.

Successful operations use the stable audit actions `auth.password.initial_set` and
`auth.password.reset`, targeted at `accounts.user` and attributed to that user after email
ownership has been proven. Only the method is recorded in metadata. These events are presented
safely in My Activity and Security Activity; low-level email-OTP events remain hidden from those
projections.

## Consequences

The account lifecycle now supports administrator-created accounts becoming user-owned credentials
without exposing passwords to administrators or revealing account existence through the request
API. Password recovery remains dependent on control of the current registered email; support-led
identity re-proofing and account invitations are future work. The canonical OpenAPI artifact is
updated with the two public operations and their explicit response/error schemas.
