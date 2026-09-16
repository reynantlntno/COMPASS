"""Test-only environment bootstrap before pytest-django initializes Django."""

# Environment must be populated before importing the production settings module.
# ruff: noqa: E402, F403, I001

import os


_TEST_ENV = {
    "APP_ENV": "local-staging",
    "DEBUG": "true",
    "SECRET_KEY": "test-only-secret-key",
    "ALLOWED_HOSTS": "testserver,localhost,127.0.0.1",
    "CSRF_TRUSTED_ORIGINS": "http://testserver,http://localhost",
    "POSTGRES_DB": "compass_test",
    "POSTGRES_USER": "compass",
    "POSTGRES_PASSWORD": "test-password",
    "POSTGRES_HOST": "127.0.0.1",
    "POSTGRES_PORT": "5432",
    "REDIS_URL": "redis://127.0.0.1:6379/0",
    "REDIS_CACHE_URL": "redis://127.0.0.1:6379/1",
    "REDIS_RATE_LIMIT_URL": "redis://127.0.0.1:6379/2",
    "REDIS_IDEMPOTENCY_URL": "redis://127.0.0.1:6379/3",
    "S3_BUCKET_NAME": "compass-test",
    "S3_ACCESS_KEY_ID": "test-access",
    "S3_SECRET_ACCESS_KEY": "test-secret",
    "S3_ENDPOINT_URL": "http://127.0.0.1:9000",
    "SMTP_HOST": "127.0.0.1",
    "SMTP_PORT": "1025",
    "DEFAULT_FROM_EMAIL": "no-reply@testserver",
    "TURNSTILE_ENABLED": "false",
    "API_DOCS_ENABLED": "true",
}

for _name, _value in _TEST_ENV.items():
    os.environ.setdefault(_name, _value)

from config.settings import *  # noqa: E402, F403
