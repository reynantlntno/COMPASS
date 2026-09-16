"""Explicit PyOTP-backed TOTP enrollment, verification, and recovery-code services."""

from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import pyotp
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.utils import timezone

from compass.audit.context import AuditContext
from compass.audit.services import record_event
from compass.authentication.actions import (
    AUTH_MFA_RECOVERY_CODE_FAILED,
    AUTH_MFA_RECOVERY_CODE_USED,
    AUTH_MFA_RECOVERY_CODES_REGENERATED,
    AUTH_MFA_TOTP_DISABLED,
    AUTH_MFA_TOTP_ENROLLED,
    AUTH_MFA_TOTP_FAILED,
    AUTH_MFA_TOTP_SETUP_STARTED,
    AUTH_MFA_TOTP_VERIFIED,
)
from compass.authentication.crypto import decrypt_totp_secret, encrypt_totp_secret
from compass.authentication.models import AuthSession, RecoveryCode, TOTPFactor
from compass.authentication.sessions import revoke_all_trusted_sessions

User = get_user_model()
TOTP_CODE_RE = re.compile(r"^\d{6}$", re.ASCII)
RECOVERY_CODE_RE = re.compile(r"^[A-Z2-9]{12}$", re.ASCII)
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class TOTPAlreadyConfigured(RuntimeError):
    """Raised when an active TOTP factor already exists."""


class TOTPEnrollmentMissing(RuntimeError):
    """Raised when confirmation is attempted without a pending factor."""


class TOTPNotConfigured(RuntimeError):
    """Raised when an operation needs an active TOTP factor."""


@dataclass(frozen=True, slots=True)
class TOTPVerification:
    valid: bool
    replayed: bool = False
    time_step: int | None = None


@dataclass(frozen=True, slots=True)
class TOTPSetupResult:
    factor_id: uuid.UUID
    provisioning_uri: str

    def __repr__(self) -> str:
        return f"TOTPSetupResult(factor_id={self.factor_id!s})"


@dataclass(frozen=True, slots=True)
class TOTPConfirmationResult:
    recovery_codes: tuple[str, ...]

    def __repr__(self) -> str:
        return "TOTPConfirmationResult(recovery_codes=<redacted>)"


@dataclass(frozen=True, slots=True)
class MFAResetResult:
    """Counts from a low-level MFA reset; no secret material is carried in the result."""

    disabled_factor_count: int
    removed_pending_factor_count: int
    invalidated_recovery_code_count: int

    @property
    def changed(self) -> bool:
        return any(
            (
                self.disabled_factor_count,
                self.removed_pending_factor_count,
                self.invalidated_recovery_code_count,
            )
        )


def active_totp_factor(user_id):
    return TOTPFactor.objects.filter(
        user_id=user_id,
        confirmed_at__isnull=False,
        disabled_at__isnull=True,
    ).first()


def has_active_totp_factor(user_id) -> bool:
    return TOTPFactor.objects.filter(
        user_id=user_id,
        confirmed_at__isnull=False,
        disabled_at__isnull=True,
    ).exists()


def mfa_required_for_user(user) -> bool:
    """Apply opt-in factor policy plus future role-specific mandatory policy."""

    role = getattr(user, "role", None)
    role_code = getattr(role, "code", None)
    if role_code in settings.AUTH_MFA_REQUIRED_ROLE_CODES:
        return True
    return has_active_totp_factor(user.pk)


def _validate_totp_code(code: str) -> str | None:
    if not isinstance(code, str):
        return None
    normalized = code.strip()
    return normalized if TOTP_CODE_RE.fullmatch(normalized) else None


def normalize_recovery_code(code: str) -> str | None:
    if not isinstance(code, str):
        return None
    normalized = re.sub(r"[-\s]", "", code).upper()
    return normalized if RECOVERY_CODE_RE.fullmatch(normalized) else None


def _totp_for_secret(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(
        secret,
        digits=settings.AUTH_TOTP_DIGITS,
        interval=settings.AUTH_TOTP_INTERVAL_SECONDS,
    )


def _verify_totp_value(
    encrypted_secret: str,
    code: str,
    *,
    last_verified_time_step: int | None = None,
    now: datetime | None = None,
) -> TOTPVerification:
    normalized = _validate_totp_code(code)
    if normalized is None:
        # Keep malformed input on the same verification path without ever logging it.
        return TOTPVerification(valid=False)
    current = now or timezone.now()
    secret = decrypt_totp_secret(encrypted_secret)
    totp = _totp_for_secret(secret)
    if not totp.verify(
        normalized,
        for_time=current,
        valid_window=settings.AUTH_TOTP_VALID_WINDOW,
    ):
        return TOTPVerification(valid=False)

    current_step = totp.timecode(current)
    offsets = sorted(
        range(-settings.AUTH_TOTP_VALID_WINDOW, settings.AUTH_TOTP_VALID_WINDOW + 1),
        key=abs,
    )
    matching_steps: list[int] = []
    for offset in offsets:
        candidate_time = current + timedelta(seconds=offset * settings.AUTH_TOTP_INTERVAL_SECONDS)
        if totp.verify(normalized, for_time=candidate_time, valid_window=0):
            matching_steps.append(current_step + offset)
    if not matching_steps:
        return TOTPVerification(valid=False)
    matched_step = matching_steps[0]
    if last_verified_time_step is not None and matched_step <= last_verified_time_step:
        return TOTPVerification(valid=False, replayed=True, time_step=matched_step)
    return TOTPVerification(valid=True, time_step=matched_step)


def _new_recovery_code() -> str:
    return "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(12))


def display_recovery_code(normalized_code: str) -> str:
    return "-".join(
        normalized_code[index : index + 4] for index in range(0, len(normalized_code), 4)
    )


def invalidate_recovery_codes(*, user_id, now: datetime | None = None) -> int:
    """Invalidate every still-usable recovery code for a future security-reset workflow."""

    current = now or timezone.now()
    codes = RecoveryCode.objects.select_for_update().filter(
        user_id=user_id,
        used_at__isnull=True,
        invalidated_at__isnull=True,
    )
    count = 0
    for code in codes:
        code.invalidated_at = current
        code.save(update_fields=["invalidated_at"])
        count += 1
    return count


def _replace_recovery_codes_locked(user_id, *, now: datetime) -> tuple[str, ...]:
    invalidate_recovery_codes(user_id=user_id, now=now)
    batch_id = uuid.uuid4()
    plaintext: list[str] = []
    records: list[RecoveryCode] = []
    for _index in range(10):
        normalized = _new_recovery_code()
        plaintext.append(display_recovery_code(normalized))
        records.append(
            RecoveryCode(
                user_id=user_id,
                batch_id=batch_id,
                code_hash=make_password(normalized),
                created_at=now,
            )
        )
    RecoveryCode.objects.bulk_create(records)
    return tuple(plaintext)


def start_totp_enrollment(
    *, user, context: AuditContext, now: datetime | None = None
) -> TOTPSetupResult:
    if not getattr(user, "pk", None) or not getattr(user, "is_active", False):
        raise TOTPNotConfigured("an active user is required")
    current = now or timezone.now()
    with transaction.atomic():
        locked_user = User.objects.select_for_update().get(pk=user.pk)
        if not locked_user.is_active:
            raise TOTPNotConfigured("an active user is required")
        if has_active_totp_factor(locked_user.pk):
            raise TOTPAlreadyConfigured("TOTP is already enabled")
        pending = (
            TOTPFactor.objects.select_for_update()
            .filter(
                user_id=locked_user.pk,
                confirmed_at__isnull=True,
                disabled_at__isnull=True,
            )
            .first()
        )
        secret = pyotp.random_base32()
        encrypted_secret = encrypt_totp_secret(secret)
        if pending is None:
            pending = TOTPFactor.objects.create(
                user=locked_user,
                encrypted_secret=encrypted_secret,
                created_at=current,
            )
        else:
            pending.encrypted_secret = encrypted_secret
            pending.created_at = current
            pending.last_verified_time_step = None
            pending.save(
                update_fields=["encrypted_secret", "created_at", "last_verified_time_step"]
            )
        record_event(
            context=context,
            action=AUTH_MFA_TOTP_SETUP_STARTED,
            outcome="SUCCESS",
            target_type="auth.totpfactor",
            target_id=pending.pk,
            metadata={"method": "totp"},
        )
        uri = _totp_for_secret(secret).provisioning_uri(
            name=locked_user.email,
            issuer_name=settings.AUTH_TOTP_ISSUER_NAME,
        )
    return TOTPSetupResult(factor_id=pending.pk, provisioning_uri=uri)


def confirm_totp_enrollment(
    *, user, code: str, context: AuditContext, now: datetime | None = None
) -> TOTPConfirmationResult | None:
    current = now or timezone.now()
    with transaction.atomic():
        factor = (
            TOTPFactor.objects.select_for_update()
            .filter(
                user_id=user.pk,
                confirmed_at__isnull=True,
                disabled_at__isnull=True,
            )
            .first()
        )
        if factor is None:
            raise TOTPEnrollmentMissing("no pending TOTP enrollment exists")
        verification = _verify_totp_value(factor.encrypted_secret, code, now=current)
        if not verification.valid:
            record_event(
                context=context,
                action=AUTH_MFA_TOTP_FAILED,
                outcome="DENIED",
                target_type="auth.totpfactor",
                target_id=factor.pk,
                metadata={"stage": "enrollment"},
            )
            return None
        factor.confirmed_at = current
        factor.last_verified_time_step = verification.time_step
        factor.save(update_fields=["confirmed_at", "last_verified_time_step"])
        recovery_codes = _replace_recovery_codes_locked(user.pk, now=current)
        record_event(
            context=context,
            action=AUTH_MFA_TOTP_ENROLLED,
            outcome="SUCCESS",
            target_type="auth.totpfactor",
            target_id=factor.pk,
            metadata={"code_count": len(recovery_codes)},
        )
    return TOTPConfirmationResult(recovery_codes=recovery_codes)


def verify_totp_for_login(*, user, code: str, now: datetime | None = None) -> TOTPVerification:
    current = now or timezone.now()
    factor = (
        TOTPFactor.objects.select_for_update()
        .filter(
            user_id=user.pk,
            confirmed_at__isnull=False,
            disabled_at__isnull=True,
        )
        .first()
    )
    if factor is None:
        return TOTPVerification(valid=False)
    verification = _verify_totp_value(
        factor.encrypted_secret,
        code,
        last_verified_time_step=factor.last_verified_time_step,
        now=current,
    )
    if verification.valid:
        factor.last_verified_time_step = verification.time_step
        factor.save(update_fields=["last_verified_time_step"])
    return verification


def verify_totp_for_session(
    *, user, session: AuthSession, code: str, context: AuditContext, now: datetime | None = None
) -> TOTPVerification:
    current = now or timezone.now()
    with transaction.atomic():
        factor = (
            TOTPFactor.objects.select_for_update()
            .filter(
                user_id=user.pk,
                confirmed_at__isnull=False,
                disabled_at__isnull=True,
            )
            .first()
        )
        if factor is None:
            verification = TOTPVerification(valid=False)
        else:
            verification = _verify_totp_value(
                factor.encrypted_secret,
                code,
                last_verified_time_step=factor.last_verified_time_step,
                now=current,
            )
            if verification.valid:
                factor.last_verified_time_step = verification.time_step
                factor.save(update_fields=["last_verified_time_step"])
                locked_session = AuthSession.objects.select_for_update().get(pk=session.pk)
                locked_session.mfa_verified_at = current
                locked_session.save(update_fields=["mfa_verified_at"])
        if verification.valid:
            record_event(
                context=context,
                action=AUTH_MFA_TOTP_VERIFIED,
                outcome="SUCCESS",
                target_type="auth.totpfactor",
                target_id=factor.pk if factor is not None else None,
                metadata={"stage": "step_up"},
            )
        else:
            record_event(
                context=context,
                action=AUTH_MFA_TOTP_FAILED,
                outcome="DENIED",
                target_type="auth.totpfactor" if factor is not None else None,
                target_id=factor.pk if factor is not None else None,
                metadata={"stage": "step_up"},
            )
    return verification


def consume_recovery_code(
    *, user, code: str, context: AuditContext, now: datetime | None = None
) -> RecoveryCode | None:
    current = now or timezone.now()
    normalized = normalize_recovery_code(code)
    candidate_value = normalized or ""
    with transaction.atomic():
        candidates = RecoveryCode.objects.select_for_update().filter(
            user_id=user.pk,
            used_at__isnull=True,
            invalidated_at__isnull=True,
        )
        matched: RecoveryCode | None = None
        for candidate in candidates:
            if check_password(candidate_value, candidate.code_hash):
                matched = candidate
                break
        if matched is None:
            record_event(
                context=context,
                action=AUTH_MFA_RECOVERY_CODE_FAILED,
                outcome="DENIED",
                target_type="accounts.user",
                target_id=user.pk,
                metadata={},
            )
            return None
        matched.used_at = current
        matched.save(update_fields=["used_at"])
        remaining = RecoveryCode.objects.filter(
            user_id=user.pk,
            used_at__isnull=True,
            invalidated_at__isnull=True,
        ).count()
        record_event(
            context=context,
            action=AUTH_MFA_RECOVERY_CODE_USED,
            outcome="SUCCESS",
            target_type="auth.recoverycode",
            target_id=matched.pk,
            metadata={"remaining": remaining},
        )
    return matched


def regenerate_recovery_codes(
    *, user, session: AuthSession, context: AuditContext, now: datetime | None = None
) -> tuple[str, ...]:
    from compass.authentication.sessions import require_recent_mfa

    require_recent_mfa(session, now=now)
    current = now or timezone.now()
    with transaction.atomic():
        if not has_active_totp_factor(user.pk):
            raise TOTPNotConfigured("TOTP is not enabled")
        codes = _replace_recovery_codes_locked(user.pk, now=current)
        record_event(
            context=context,
            action=AUTH_MFA_RECOVERY_CODES_REGENERATED,
            outcome="SUCCESS",
            target_type="accounts.user",
            target_id=user.pk,
            metadata={"count": len(codes)},
        )
    return codes


def reset_totp_state(*, user_id, now: datetime | None = None) -> MFAResetResult:
    """Reset stored MFA state for an administrative security workflow.

    This low-level primitive intentionally has no authorization or audit behavior. Callers must
    choose the self-service or administrative policy explicitly; neither workflow receives a
    plaintext secret or replacement recovery codes from this operation.
    """

    current = now or timezone.now()
    with transaction.atomic():
        factors = list(TOTPFactor.objects.select_for_update().filter(user_id=user_id))
        disabled_factor_count = 0
        removed_pending_factor_count = 0
        for factor in factors:
            if factor.confirmed_at is None and factor.disabled_at is None:
                factor.delete()
                removed_pending_factor_count += 1
            elif factor.confirmed_at is not None and factor.disabled_at is None:
                factor.disabled_at = current
                factor.save(update_fields=["disabled_at"])
                disabled_factor_count += 1
        invalidated_recovery_code_count = invalidate_recovery_codes(
            user_id=user_id,
            now=current,
        )
    return MFAResetResult(
        disabled_factor_count=disabled_factor_count,
        removed_pending_factor_count=removed_pending_factor_count,
        invalidated_recovery_code_count=invalidated_recovery_code_count,
    )


def disable_totp(
    *, user, session: AuthSession, context: AuditContext, now: datetime | None = None
) -> None:
    from compass.authentication.sessions import require_recent_mfa

    require_recent_mfa(session, now=now)
    current = now or timezone.now()
    with transaction.atomic():
        factor = (
            TOTPFactor.objects.select_for_update()
            .filter(
                user_id=user.pk,
                confirmed_at__isnull=False,
                disabled_at__isnull=True,
            )
            .first()
        )
        if factor is None:
            raise TOTPNotConfigured("TOTP is not enabled")
        factor.disabled_at = current
        factor.save(update_fields=["disabled_at"])
        invalidate_recovery_codes(user_id=user.pk, now=current)
        revoke_all_trusted_sessions(
            user_id=user.pk,
            context=context,
            reason="mfa_disabled",
            now=current,
        )
        record_event(
            context=context,
            action=AUTH_MFA_TOTP_DISABLED,
            outcome="SUCCESS",
            target_type="auth.totpfactor",
            target_id=factor.pk,
            metadata={},
        )


__all__ = [
    "TOTPAlreadyConfigured",
    "TOTPConfirmationResult",
    "TOTPEnrollmentMissing",
    "MFAResetResult",
    "TOTPNotConfigured",
    "TOTPSetupResult",
    "TOTPVerification",
    "active_totp_factor",
    "confirm_totp_enrollment",
    "consume_recovery_code",
    "disable_totp",
    "display_recovery_code",
    "has_active_totp_factor",
    "invalidate_recovery_codes",
    "mfa_required_for_user",
    "normalize_recovery_code",
    "regenerate_recovery_codes",
    "reset_totp_state",
    "start_totp_enrollment",
    "verify_totp_for_login",
    "verify_totp_for_session",
]
