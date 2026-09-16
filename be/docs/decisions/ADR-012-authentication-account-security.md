# ADR-012: Server-managed authentication and account security

## Context

COMPASS needs revocable browser authentication, MFA state, trusted-browser state, and future
security reset operations. The existing backend is stateful, already uses PostgreSQL and Redis,
and uses Django's cookie/CSRF machinery. JWT, browser `localStorage`, and a second authentication
framework would make revocation and session inspection less direct without a demonstrated product
requirement.

## Decision

Use a random server-managed opaque credential in an `HttpOnly` cookie. `AuthSession` stores only a
SHA-256 digest plus expiry, revocation, recent-MFA timestamp, and descriptive request metadata.
`TrustedSession` and short-lived `LoginChallenge` use the same digest-only pattern. Protected Ninja
routes have one canonical cookie authenticator that rejects expired/revoked sessions and inactive
users. Session listing and explicit one/all/other revocation remain synchronous PostgreSQL state
changes and emit meaningful Audit Trail events.

Use Django's CSRF middleware and documented SPA header flow: the authentication cookies remain
`HttpOnly`, while the separate CSRF cookie/token is available to the frontend. Live-staging
requires Secure auth cookies; cookie SameSite, domain, path, and lifetimes are settings-driven.

Use PyOTP for the narrow TOTP integration instead of django-otp. PyOTP supplies the maintained,
explicit RFC 6238 implementation needed here without introducing django-otp's broader device,
middleware, and authentication framework. TOTP secrets are encrypted with Fernet from the
deployment-provided `AUTH_TOTP_ENCRYPTION_KEY`; this is narrow protection for recoverable MFA
material, not a general COMPASS encryption or key-rotation subsystem. Recovery codes and email OTP
codes use Django password hashing and are never persisted in plaintext. Email OTP remains distinct
from TOTP, with short-lived, bounded, hash-only challenges and Celery delivery through the existing
SMTP adapter.

MFA policy is separate from capabilities. An enrolled TOTP factor requires MFA at the next login;
role-specific mandatory MFA can be enabled through configuration without hardcoding institutional
policy. Trusted browser credentials can satisfy that MFA prompt only after correct password
verification, have configurable expiry, and are explicitly revocable. `require_recent_mfa()` is
the shared step-up boundary for sensitive future operations such as disabling TOTP or regenerating
recovery codes. Authentication abuse controls reuse the existing Redis limiter across IP,
identifier, user, and combination dimensions. Turnstile is an additional configurable,
server-side check for relevant anonymous/high-abuse flows, never a replacement for rate limiting.

Critical authentication state changes and meaningful failures are audited synchronously through the
existing `record_event()` service without passwords, hashes, tokens, MFA codes, OTP values, or
Turnstile values in metadata. Password verification uses Django's built-in hashing APIs. Password
reset, account administration, organizational scope, Activity Log, Audit read APIs, and a full
recovery workflow are deferred.

## Consequences

Revocation, session inspection, MFA step-up, and security resets have clear server-side state and
do not depend on browser fingerprints. The application must protect the TOTP encryption key and
maintain the configured cookie/origin/proxy policy. Email delivery is asynchronous and transient;
the current email OTP service is an internal foundation rather than a public account-recovery
endpoint. A future service may invoke the existing revocation and recent-MFA primitives without
creating a competing authentication mechanism.
