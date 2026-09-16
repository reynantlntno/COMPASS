# ADR-005: Use an S3-compatible storage abstraction

## Context

Uploads and generated files must survive application-container replacement. Local MinIO is useful
for parity testing, while live-staging may use a managed S3-compatible provider.

## Decision

Use Django's storage interface backed by `django-storages`/boto3. The application-facing
`ObjectStorage` adapter exposes only storage operations. Local-staging points to private MinIO;
live-staging points to an externally managed S3-compatible endpoint. Use separate `media/` and
`static/` key prefixes and private objects by default.

## Consequences

Domain code does not depend on MinIO SDK calls. Credentials, endpoint, addressing style, TLS
verification, retention, backup, and lifecycle policy remain deployment configuration.
