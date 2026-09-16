"""Narrow authenticated encryption boundary for TOTP material."""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def _fernet() -> Fernet:
    key = settings.AUTH_TOTP_ENCRYPTION_KEY
    if not key:
        raise ImproperlyConfigured(
            "AUTH_TOTP_ENCRYPTION_KEY is required before TOTP enrollment or verification"
        )
    try:
        return Fernet(key.encode("ascii"))
    except (UnicodeEncodeError, TypeError, ValueError) as exc:
        raise ImproperlyConfigured("AUTH_TOTP_ENCRYPTION_KEY is not a valid Fernet key") from exc


def encrypt_totp_secret(secret: str) -> str:
    if not isinstance(secret, str) or not secret:
        raise ValueError("TOTP secret must be a non-empty string")
    return _fernet().encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_totp_secret(encrypted_secret: str) -> str:
    if not isinstance(encrypted_secret, str) or not encrypted_secret:
        raise ValueError("encrypted TOTP secret must be a non-empty string")
    try:
        return _fernet().decrypt(encrypted_secret.encode("ascii")).decode("ascii")
    except (UnicodeEncodeError, UnicodeDecodeError, InvalidToken) as exc:
        raise ImproperlyConfigured("stored TOTP secret could not be decrypted") from exc
