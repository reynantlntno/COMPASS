"""Append-only application model for the COMPASS Audit Trail."""

from __future__ import annotations

import re
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone

from compass.audit.metadata import validate_metadata

ACTION_PATTERN = r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$"
TARGET_TYPE_PATTERN = r"^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$"
ACTION_RE = re.compile(ACTION_PATTERN, re.ASCII)
TARGET_TYPE_RE = re.compile(TARGET_TYPE_PATTERN, re.ASCII)
MAX_ACTION_LENGTH = 128
MAX_TARGET_TYPE_LENGTH = 128
MAX_TARGET_ID_LENGTH = 255
MAX_USER_AGENT_SUMMARY_LENGTH = 256


class AuditEventAppendOnlyError(RuntimeError):
    """Raised when application code attempts to mutate or delete an audit event."""


class AuditActorType(models.TextChoices):
    USER = "USER", "User"
    SYSTEM = "SYSTEM", "System"
    ANONYMOUS = "ANONYMOUS", "Anonymous"


class AuditOutcome(models.TextChoices):
    SUCCESS = "SUCCESS", "Success"
    DENIED = "DENIED", "Denied"
    FAILED = "FAILED", "Failed"


ActorType = AuditActorType
Outcome = AuditOutcome


class AuditEventQuerySet(models.QuerySet):
    """Prevent normal ORM bulk mutation paths for audit rows."""

    def update(self, **kwargs):
        raise AuditEventAppendOnlyError("AuditEvent rows cannot be updated")

    def delete(self):
        raise AuditEventAppendOnlyError("AuditEvent rows cannot be deleted")

    def bulk_update(self, objs, fields, batch_size=None):
        raise AuditEventAppendOnlyError("AuditEvent rows cannot be updated")


class AuditEvent(models.Model):
    """A small, attributable record of a meaningful business or security action.

    Append-only is enforced at the application model/queryset boundary. PostgreSQL-level
    tamper-proofing and retention are intentionally outside this foundation.
    """

    ActorType = AuditActorType
    Outcome = AuditOutcome

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    occurred_at = models.DateTimeField(default=timezone.now, editable=False)
    actor_type = models.CharField(max_length=9, choices=AuditActorType.choices)
    actor_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="audit_events",
        blank=True,
        null=True,
        db_index=False,
    )
    action = models.CharField(
        max_length=MAX_ACTION_LENGTH,
        validators=[
            RegexValidator(
                regex=ACTION_PATTERN,
                message="action must be a lowercase dotted identifier",
            )
        ],
    )
    outcome = models.CharField(max_length=7, choices=AuditOutcome.choices)
    target_type = models.CharField(
        max_length=MAX_TARGET_TYPE_LENGTH,
        blank=True,
        null=True,
        validators=[
            RegexValidator(
                regex=TARGET_TYPE_PATTERN,
                message="target_type must be a lowercase dotted identifier",
            )
        ],
    )
    target_id = models.CharField(max_length=MAX_TARGET_ID_LENGTH, blank=True, null=True)
    request_id = models.UUIDField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(
        protocol="both",
        unpack_ipv4=True,
        blank=True,
        null=True,
    )
    user_agent_summary = models.CharField(
        max_length=MAX_USER_AGENT_SUMMARY_LENGTH,
        blank=True,
        null=True,
    )
    metadata = models.JSONField(default=dict, blank=True)

    objects = models.Manager.from_queryset(AuditEventQuerySet)()

    class Meta:
        default_permissions = ()
        ordering = ("-occurred_at", "-id")
        constraints = [
            models.CheckConstraint(
                condition=(
                    (models.Q(actor_type=AuditActorType.USER) & models.Q(actor_user__isnull=False))
                    | (
                        models.Q(actor_type__in=[AuditActorType.SYSTEM, AuditActorType.ANONYMOUS])
                        & models.Q(actor_user__isnull=True)
                    )
                ),
                name="audit_event_actor_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(outcome__in=AuditOutcome.values),
                name="audit_event_outcome_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(action__regex=ACTION_PATTERN),
                name="audit_event_action_format",
            ),
            models.CheckConstraint(
                condition=(
                    (models.Q(target_type__isnull=True) & models.Q(target_id__isnull=True))
                    | (models.Q(target_type__isnull=False) & models.Q(target_id__isnull=False))
                ),
                name="audit_event_target_pair",
            ),
        ]
        indexes = [
            models.Index(fields=("-occurred_at",), name="audit_evt_occurred_idx"),
            models.Index(fields=("action", "-occurred_at"), name="audit_evt_action_time_idx"),
            models.Index(fields=("actor_user", "-occurred_at"), name="audit_evt_actor_time_idx"),
            models.Index(
                fields=("target_type", "target_id", "-occurred_at"),
                name="audit_evt_target_time_idx",
            ),
            models.Index(fields=("request_id",), name="audit_evt_request_idx"),
        ]

    def clean(self) -> None:
        super().clean()
        errors: dict[str, str] = {}

        if self.actor_type == AuditActorType.USER and self.actor_user_id is None:
            errors["actor_user"] = "USER audit events require actor_user"
        elif self.actor_type in {AuditActorType.SYSTEM, AuditActorType.ANONYMOUS}:
            if self.actor_user_id is not None:
                errors["actor_user"] = "SYSTEM and ANONYMOUS audit events cannot have actor_user"
        elif self.actor_type not in AuditActorType.values:
            errors["actor_type"] = "actor_type must be USER, SYSTEM, or ANONYMOUS"

        if self.outcome not in AuditOutcome.values:
            errors["outcome"] = "outcome must be SUCCESS, DENIED, or FAILED"
        if not isinstance(self.action, str) or not ACTION_RE.fullmatch(self.action):
            errors["action"] = "action must be a lowercase dotted identifier"

        if isinstance(self.target_type, str):
            self.target_type = self.target_type.strip() or None
        if isinstance(self.target_id, str):
            self.target_id = self.target_id.strip() or None
        if (self.target_type is None) != (self.target_id is None):
            errors["target_id"] = "target_type and target_id must be provided together"
        if self.target_type is not None and (
            not isinstance(self.target_type, str) or not TARGET_TYPE_RE.fullmatch(self.target_type)
        ):
            errors["target_type"] = "target_type must be a lowercase dotted identifier"
        if self.target_id is not None:
            if (
                not isinstance(self.target_id, str)
                or len(self.target_id) > MAX_TARGET_ID_LENGTH
                or any(ord(character) < 32 or ord(character) == 127 for character in self.target_id)
            ):
                errors["target_id"] = "target_id contains invalid characters or is too long"

        try:
            self.metadata = validate_metadata(self.metadata)
        except ValueError as exc:
            errors["metadata"] = str(exc)

        if self.user_agent_summary is not None and (
            not isinstance(self.user_agent_summary, str)
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.user_agent_summary
            )
        ):
            errors["user_agent_summary"] = "user_agent_summary must not contain control characters"

        if errors:
            raise ValidationError(errors)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise AuditEventAppendOnlyError("AuditEvent rows cannot be updated")
        self.full_clean()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise AuditEventAppendOnlyError("AuditEvent rows cannot be deleted")

    def __str__(self) -> str:
        return f"{self.occurred_at.isoformat()} {self.action} {self.outcome}"
