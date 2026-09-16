import uuid
from io import StringIO
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.management import CommandError, call_command
from django.db import transaction
from django.db.models.deletion import ProtectedError
from django.test import RequestFactory, override_settings

from compass.accounts.models import Role
from compass.audit.actions import ACCOUNT_CREATED, IDENTITY_POLICY_SYNCED
from compass.audit.context import AuditContext
from compass.audit.models import (
    AuditEvent,
    AuditEventAppendOnlyError,
    AuditOutcome,
)
from compass.audit.services import record_event

User = get_user_model()


def make_user(*, email: str = "audit-user@example.edu"):
    role = Role.objects.create(code="AUDIT_TEST", name="Audit test role")
    return User.objects.create_user(
        email=email,
        password="a-test-password",
        role=role,
        first_name="Audit",
        last_name="User",
    )


def make_event_context(*, user=None, request_id=None):
    if user is not None:
        return AuditContext.user(user, request_id=request_id)
    return AuditContext.system(request_id=request_id)


@pytest.mark.django_db
def test_record_event_supports_user_system_and_anonymous_actors():
    request_id = uuid.uuid4()
    user = make_user()

    user_event = record_event(
        context=AuditContext.user(
            user,
            request_id=request_id,
            ip_address="203.0.113.10",
            user_agent_summary="COMPASS test client",
        ),
        action="accounts.viewed",
        outcome=AuditOutcome.SUCCESS,
        target_type="accounts.user",
        target_id=user.pk,
        metadata={"view": "identity"},
    )
    system_event = record_event(
        context=AuditContext.system(request_id=request_id),
        action="identity.policy.synced",
        outcome=AuditOutcome.SUCCESS,
    )
    anonymous_event = record_event(
        context=AuditContext.anonymous(request_id=request_id),
        action="auth.login.failed",
        outcome=AuditOutcome.DENIED,
    )

    assert user_event.id.version == 4
    assert user_event.actor_type == AuditEvent.ActorType.USER
    assert user_event.actor_user_id == user.pk
    assert str(user_event.request_id) == str(request_id)
    assert user_event.ip_address == "203.0.113.10"
    assert user_event.user_agent_summary == "COMPASS test client"
    assert user_event.metadata == {"view": "identity"}
    assert system_event.actor_type == AuditEvent.ActorType.SYSTEM
    assert system_event.actor_user_id is None
    assert anonymous_event.actor_type == AuditEvent.ActorType.ANONYMOUS
    assert anonymous_event.actor_user_id is None


@pytest.mark.django_db
def test_audit_model_invariants_reject_invalid_actor_and_target_combinations():
    user = make_user()

    invalid_events = [
        AuditEvent(
            actor_type=AuditEvent.ActorType.USER,
            action="accounts.viewed",
            outcome=AuditOutcome.SUCCESS,
        ),
        AuditEvent(
            actor_type=AuditEvent.ActorType.SYSTEM,
            actor_user=user,
            action="accounts.viewed",
            outcome=AuditOutcome.SUCCESS,
        ),
        AuditEvent(
            actor_type=AuditEvent.ActorType.SYSTEM,
            action="accounts.viewed",
            outcome=AuditOutcome.SUCCESS,
            target_type="accounts.user",
        ),
        AuditEvent(
            actor_type=AuditEvent.ActorType.SYSTEM,
            action="accounts.viewed",
            outcome=AuditOutcome.SUCCESS,
            target_id=str(user.pk),
        ),
    ]

    for event in invalid_events:
        with pytest.raises(ValidationError):
            event.full_clean()

    with pytest.raises(ValueError, match="target_type and target_id"):
        record_event(
            context=AuditContext.system(),
            action="accounts.viewed",
            outcome=AuditOutcome.SUCCESS,
            target_type="accounts.user",
        )


@pytest.mark.django_db
@pytest.mark.parametrize("outcome", AuditOutcome.values)
def test_valid_outcomes_are_accepted(outcome):
    event = record_event(
        context=AuditContext.system(),
        action="security.check.completed",
        outcome=outcome,
    )

    assert event.outcome == outcome


@pytest.mark.django_db
def test_action_and_outcome_are_validated_by_recording_service():
    for action in ("Accounts.Viewed", "accounts viewed", "accounts", ".accounts.viewed"):
        with pytest.raises(ValueError, match="action"):
            record_event(
                context=AuditContext.system(),
                action=action,
                outcome=AuditOutcome.SUCCESS,
            )

    with pytest.raises(ValueError, match="outcome"):
        record_event(
            context=AuditContext.system(),
            action="accounts.viewed",
            outcome="UNKNOWN",
        )


def test_audit_context_reuses_request_id_trusted_ip_and_safe_user_agent_summary():
    request_id = str(uuid.uuid4())
    factory = RequestFactory()
    request = factory.get(
        "/",
        REMOTE_ADDR="10.0.0.5",
        HTTP_CF_CONNECTING_IP="203.0.113.10",
        HTTP_USER_AGENT="Browser\r\nInjected " + ("x" * 400),
    )
    request.request_id = request_id

    with override_settings(TRUSTED_PROXY_CIDRS=["10.0.0.0/8"]):
        context = AuditContext.from_request(request)

    assert context.actor_type == AuditEvent.ActorType.ANONYMOUS
    assert context.request_id == request_id
    assert context.ip_address == "203.0.113.10"
    assert len(context.user_agent_summary) == 256
    assert "\r" not in context.user_agent_summary
    assert "\n" not in context.user_agent_summary

    request = factory.get(
        "/",
        REMOTE_ADDR="198.51.100.5",
        HTTP_CF_CONNECTING_IP="203.0.113.10",
    )
    request.request_id = request_id
    with override_settings(TRUSTED_PROXY_CIDRS=["10.0.0.0/8"]):
        untrusted_context = AuditContext.from_request(request)
    assert untrusted_context.ip_address == "198.51.100.5"


@pytest.mark.django_db
def test_metadata_is_explicit_small_json_and_does_not_serialize_models_or_secrets():
    user = make_user()
    source = {"changed_fields": ["first_name", "last_name"]}
    event = record_event(
        context=AuditContext.user(user),
        action="accounts.updated",
        outcome=AuditOutcome.SUCCESS,
        metadata=source,
    )
    source["changed_fields"].append("email")

    assert event.metadata == {"changed_fields": ["first_name", "last_name"]}

    with pytest.raises(ValueError, match="not allowed"):
        record_event(
            context=AuditContext.system(),
            action="accounts.created",
            outcome=AuditOutcome.SUCCESS,
            metadata={"password": "never-store-this"},
        )
    with pytest.raises(ValueError, match="JSON-compatible"):
        record_event(
            context=AuditContext.system(),
            action="accounts.created",
            outcome=AuditOutcome.SUCCESS,
            metadata={"user": user},
        )


@pytest.mark.django_db
def test_audit_events_are_append_only_at_model_and_queryset_boundaries():
    event = record_event(
        context=AuditContext.system(),
        action="security.check.completed",
        outcome=AuditOutcome.SUCCESS,
    )

    event.outcome = AuditOutcome.FAILED
    with pytest.raises(AuditEventAppendOnlyError):
        event.save()
    with pytest.raises(AuditEventAppendOnlyError):
        event.delete()
    with pytest.raises(AuditEventAppendOnlyError):
        AuditEvent.objects.filter(pk=event.pk).update(outcome=AuditOutcome.FAILED)
    with pytest.raises(AuditEventAppendOnlyError):
        AuditEvent.objects.filter(pk=event.pk).delete()
    with pytest.raises(AuditEventAppendOnlyError):
        AuditEvent.objects.bulk_update([event], ["outcome"])


@pytest.mark.django_db
def test_actor_user_is_protected_so_disabling_is_preferred_to_deletion():
    user = make_user()
    event = record_event(
        context=AuditContext.user(user),
        action="accounts.viewed",
        outcome=AuditOutcome.SUCCESS,
        target_type="accounts.user",
        target_id=user.pk,
    )

    with pytest.raises(ProtectedError):
        user.delete()
    assert AuditEvent.objects.filter(pk=event.pk, actor_user=user).exists()


@pytest.mark.django_db
def test_success_audit_event_rolls_back_with_surrounding_transaction():
    with pytest.raises(RuntimeError, match="rollback"):
        with transaction.atomic():
            record_event(
                context=AuditContext.system(),
                action="security.check.completed",
                outcome=AuditOutcome.SUCCESS,
            )
            raise RuntimeError("rollback")

    assert AuditEvent.objects.count() == 0


@pytest.mark.django_db
def test_state_change_and_success_audit_event_commit_together():
    role = Role.objects.create(code="ATOMIC_TEST", name="Atomic test role")

    with transaction.atomic():
        user = User.objects.create_user(
            email="atomic@example.edu",
            password="a-test-password",
            role=role,
            first_name="Atomic",
            last_name="User",
        )
        event = record_event(
            context=AuditContext.system(),
            action=ACCOUNT_CREATED,
            outcome=AuditOutcome.SUCCESS,
            target_type="accounts.user",
            target_id=user.pk,
        )

    assert User.objects.filter(pk=user.pk).exists()
    assert AuditEvent.objects.filter(pk=event.pk, target_id=str(user.pk)).exists()


@pytest.mark.django_db
def test_create_it_admin_records_system_audit_event_without_password_data():
    call_command("sync_identity_policy", stdout=StringIO())
    with patch(
        "compass.accounts.management.commands.create_it_admin.getpass.getpass",
        side_effect=["a-secure-password", "a-secure-password"],
    ):
        call_command(
            "create_it_admin",
            "--email",
            "it-admin@example.edu",
            "--first-name",
            "IT",
            "--last-name",
            "Administrator",
            stdout=StringIO(),
        )

    user = User.objects.get(email="it-admin@example.edu")
    event = AuditEvent.objects.get(action=ACCOUNT_CREATED)
    assert event.actor_type == AuditEvent.ActorType.SYSTEM
    assert event.actor_user_id is None
    assert event.target_type == "accounts.user"
    assert event.target_id == str(user.pk)
    assert event.metadata == {"role": "IT_ADMIN"}
    assert "password" not in event.metadata


@pytest.mark.django_db
def test_create_it_admin_does_not_leave_success_audit_event_on_failure_or_repeat():
    call_command("sync_identity_policy", stdout=StringIO())
    before = AuditEvent.objects.filter(action=ACCOUNT_CREATED).count()

    with patch(
        "compass.accounts.management.commands.create_it_admin.getpass.getpass",
        side_effect=["a-secure-password", "different-password"],
    ):
        with pytest.raises(CommandError, match="passwords did not match"):
            call_command(
                "create_it_admin",
                "--email",
                "it-admin@example.edu",
                "--first-name",
                "IT",
                "--last-name",
                "Administrator",
                stdout=StringIO(),
            )
    assert User.objects.count() == 0
    assert AuditEvent.objects.filter(action=ACCOUNT_CREATED).count() == before

    with patch(
        "compass.accounts.management.commands.create_it_admin.record_event",
        side_effect=RuntimeError("audit database unavailable"),
    ):
        with patch(
            "compass.accounts.management.commands.create_it_admin.getpass.getpass",
            side_effect=["a-secure-password", "a-secure-password"],
        ):
            with pytest.raises(RuntimeError, match="audit database unavailable"):
                call_command(
                    "create_it_admin",
                    "--email",
                    "it-admin@example.edu",
                    "--first-name",
                    "IT",
                    "--last-name",
                    "Administrator",
                    stdout=StringIO(),
                )
    assert User.objects.count() == 0
    assert AuditEvent.objects.filter(action=ACCOUNT_CREATED).count() == before


@pytest.mark.django_db
def test_policy_sync_records_one_event_only_when_it_changes_policy():
    call_command("sync_identity_policy", stdout=StringIO())
    assert AuditEvent.objects.filter(action=IDENTITY_POLICY_SYNCED).count() == 1
    event = AuditEvent.objects.get(action=IDENTITY_POLICY_SYNCED)
    assert event.actor_type == AuditEvent.ActorType.SYSTEM
    assert event.target_type is None
    assert event.target_id is None
    assert event.metadata["roles_created"] == 4

    call_command("sync_identity_policy", stdout=StringIO())
    assert AuditEvent.objects.filter(action=IDENTITY_POLICY_SYNCED).count() == 1


@pytest.mark.django_db
def test_policy_sync_rolls_back_if_audit_recording_fails():
    with patch(
        "compass.accounts.management.commands.sync_identity_policy.record_event",
        side_effect=RuntimeError("audit database unavailable"),
    ):
        with pytest.raises(RuntimeError, match="audit database unavailable"):
            call_command("sync_identity_policy", stdout=StringIO())

    assert Role.objects.count() == 0
    assert AuditEvent.objects.count() == 0


def test_audit_read_api_is_not_exposed():
    from django.test import Client

    response = Client().get("/api/v1/audit/events")

    assert response.status_code == 404
