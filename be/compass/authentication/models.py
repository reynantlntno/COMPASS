"""Explicit server-managed authentication and account-security state."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.db.models import F, Q
from django.utils import timezone

OPAQUE_DIGEST_LENGTH = 64
USER_AGENT_SUMMARY_LENGTH = 256


class AuthSession(models.Model):
    """A revocable, server-managed authenticated browser session."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="authentication_sessions",
    )
    token_digest = models.CharField(
        max_length=OPAQUE_DIGEST_LENGTH,
        unique=True,
        editable=False,
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    last_used_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(blank=True, null=True)
    mfa_verified_at = models.DateTimeField(blank=True, null=True)
    user_agent_summary = models.CharField(
        max_length=USER_AGENT_SUMMARY_LENGTH,
        blank=True,
        null=True,
    )
    initial_ip_address = models.GenericIPAddressField(
        protocol="both",
        unpack_ipv4=True,
        blank=True,
        null=True,
    )
    last_ip_address = models.GenericIPAddressField(
        protocol="both",
        unpack_ipv4=True,
        blank=True,
        null=True,
    )
    created_request_id = models.UUIDField(blank=True, null=True, editable=False)

    class Meta:
        default_permissions = ()
        ordering = ("-last_used_at", "-created_at", "-id")
        indexes = [
            models.Index(
                fields=("user", "revoked_at", "expires_at"),
                name="auth_session_active_idx",
            ),
            models.Index(fields=("expires_at",), name="auth_session_expiry_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(expires_at__gt=F("created_at")),
                name="auth_session_expiry_after_creation",
            ),
        ]

    def __str__(self) -> str:
        return str(self.id)


class TrustedSession(models.Model):
    """A revocable browser-held MFA trust credential, not a device fingerprint."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="trusted_authentication_sessions",
    )
    token_digest = models.CharField(
        max_length=OPAQUE_DIGEST_LENGTH,
        unique=True,
        editable=False,
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    last_used_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(blank=True, null=True)
    user_agent_summary = models.CharField(
        max_length=USER_AGENT_SUMMARY_LENGTH,
        blank=True,
        null=True,
    )
    created_ip_address = models.GenericIPAddressField(
        protocol="both",
        unpack_ipv4=True,
        blank=True,
        null=True,
    )
    last_ip_address = models.GenericIPAddressField(
        protocol="both",
        unpack_ipv4=True,
        blank=True,
        null=True,
    )
    created_request_id = models.UUIDField(blank=True, null=True, editable=False)

    class Meta:
        default_permissions = ()
        ordering = ("-last_used_at", "-created_at", "-id")
        indexes = [
            models.Index(
                fields=("user", "revoked_at", "expires_at"),
                name="auth_trusted_active_idx",
            ),
            models.Index(fields=("expires_at",), name="auth_trusted_expiry_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(expires_at__gt=F("created_at")),
                name="auth_trusted_expiry_after_creation",
            ),
        ]

    def __str__(self) -> str:
        return str(self.id)


class LoginChallenge(models.Model):
    """Short-lived pre-authentication state used before a required MFA response."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="login_challenges",
    )
    challenge_digest = models.CharField(
        max_length=OPAQUE_DIGEST_LENGTH,
        unique=True,
        editable=False,
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    expires_at = models.DateTimeField()
    primary_credentials_verified_at = models.DateTimeField(editable=False)
    allowed_methods = models.JSONField(default=list)
    trust_browser = models.BooleanField(default=False)
    consumed_at = models.DateTimeField(blank=True, null=True)
    user_agent_summary = models.CharField(
        max_length=USER_AGENT_SUMMARY_LENGTH,
        blank=True,
        null=True,
    )
    ip_address = models.GenericIPAddressField(
        protocol="both",
        unpack_ipv4=True,
        blank=True,
        null=True,
    )
    created_request_id = models.UUIDField(blank=True, null=True, editable=False)

    class Meta:
        default_permissions = ()
        ordering = ("-created_at", "-id")
        indexes = [
            models.Index(fields=("user", "expires_at"), name="auth_challenge_user_idx"),
            models.Index(fields=("expires_at",), name="auth_challenge_expiry_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(expires_at__gt=F("created_at")),
                name="auth_challenge_expiry_after_creation",
            ),
        ]

    def __str__(self) -> str:
        return str(self.id)


class TOTPFactor(models.Model):
    """One pending or confirmed TOTP factor per user, with an encrypted secret."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="totp_factors",
    )
    encrypted_secret = models.TextField(max_length=512, editable=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    confirmed_at = models.DateTimeField(blank=True, null=True)
    disabled_at = models.DateTimeField(blank=True, null=True)
    last_verified_time_step = models.BigIntegerField(blank=True, null=True)

    class Meta:
        default_permissions = ()
        ordering = ("-created_at", "-id")
        constraints = [
            models.UniqueConstraint(
                fields=("user",),
                condition=Q(disabled_at__isnull=True),
                name="auth_one_active_totp_per_user",
            ),
            models.CheckConstraint(
                condition=Q(disabled_at__isnull=True) | Q(confirmed_at__isnull=False),
                name="auth_disabled_totp_was_confirmed",
            ),
        ]

    @property
    def is_active(self) -> bool:
        return self.confirmed_at is not None and self.disabled_at is None

    def __str__(self) -> str:
        return str(self.id)


class RecoveryCode(models.Model):
    """A one-time hashed recovery code; the plaintext is never persisted."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="recovery_codes",
    )
    batch_id = models.UUIDField(default=uuid.uuid4, editable=False)
    code_hash = models.CharField(max_length=256, editable=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    used_at = models.DateTimeField(blank=True, null=True)
    invalidated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        default_permissions = ()
        ordering = ("created_at", "id")
        indexes = [
            models.Index(
                fields=("user", "used_at", "invalidated_at"),
                name="auth_recovery_active_idx",
            ),
            models.Index(fields=("user", "batch_id"), name="auth_recovery_batch_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(used_at__isnull=True) | Q(invalidated_at__isnull=True),
                name="auth_recovery_one_terminal_state",
            ),
        ]

    @property
    def is_usable(self) -> bool:
        return self.used_at is None and self.invalidated_at is None

    def __str__(self) -> str:
        return str(self.id)


class EmailOTPPurpose(models.TextChoices):
    EMAIL_VERIFICATION = "email_verification", "Email verification"
    RECOVERY = "recovery", "Recovery"
    SECURITY_CHALLENGE = "security_challenge", "Security challenge"


class EmailOTPChallenge(models.Model):
    """Short-lived email OTP state with hash-only code storage and bounded attempts."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="email_otp_challenges",
        blank=True,
        null=True,
    )
    email = models.EmailField(max_length=254)
    purpose = models.CharField(max_length=32, choices=EmailOTPPurpose.choices)
    code_hash = models.CharField(max_length=256, editable=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(blank=True, null=True)
    failed_attempt_count = models.PositiveIntegerField(default=0)
    send_count = models.PositiveIntegerField(default=1)
    last_sent_at = models.DateTimeField(default=timezone.now)
    request_id = models.UUIDField(blank=True, null=True, editable=False)

    class Meta:
        default_permissions = ()
        ordering = ("-created_at", "-id")
        indexes = [
            models.Index(
                fields=("email", "purpose", "expires_at"),
                name="auth_email_otp_lookup_idx",
            ),
            models.Index(fields=("user", "expires_at"), name="auth_email_otp_user_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(expires_at__gt=F("created_at")),
                name="auth_email_otp_expiry_after_creation",
            ),
        ]

    def __str__(self) -> str:
        return str(self.id)


__all__ = [
    "AuthSession",
    "EmailOTPChallenge",
    "EmailOTPPurpose",
    "LoginChallenge",
    "RecoveryCode",
    "TOTPFactor",
    "TrustedSession",
]
