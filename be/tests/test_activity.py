"""Focused tests for safe self-only activity projections."""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from django.test import Client
from django.utils import timezone

from compass.accounts.models import Role, User
from compass.audit.actions import ACCOUNT_CREATED, IDENTITY_POLICY_SYNCED
from compass.audit.context import AuditContext
from compass.audit.models import AuditEvent
from compass.audit.services import record_event
from compass.authentication.actions import (
    AUTH_LOGIN_FAILED,
    AUTH_LOGIN_SUCCESS,
    AUTH_LOGOUT,
    AUTH_MFA_TOTP_ENROLLED,
    AUTH_SESSION_CREATED,
    AUTH_SESSION_REVOKED,
    AUTH_TRUSTED_SESSION_CREATED,
)
from compass.authentication.models import AuthSession, TOTPFactor, TrustedSession
from compass.authentication.sessions import create_auth_session


def make_user(*, email: str) -> User:
    role, _created = Role.objects.get_or_create(
        code="STUDENT",
        defaults={"name": "Student"},
    )
    return User.objects.create_user(
        email=email,
        password="correct-password",
        role=role,
        first_name="Test",
        last_name="User",
    )


def authenticate_client(client: Client, user: User) -> None:
    issued = create_auth_session(user)
    client.cookies["compass_session"] = issued.token


def event_context(user: User) -> AuditContext:
    return AuditContext.user(
        user,
        request_id=uuid4(),
        ip_address="203.0.113.10",
        user_agent_summary="Sensitive test user-agent",
    )


def record_user_event(
    *,
    user: User,
    action: str,
    target_type: str,
    target_id,
    occurred_at,
    outcome: str = "SUCCESS",
    metadata: dict[str, object] | None = None,
) -> AuditEvent:
    return record_event(
        context=event_context(user),
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        occurred_at=occurred_at,
        metadata=metadata or {},
    )


@pytest.mark.django_db
def test_activity_endpoints_require_an_authenticated_compass_session(client):
    assert client.get("/api/v1/me/activity").status_code == 401
    assert client.get("/api/v1/me/security-activity").status_code == 401


@pytest.mark.django_db
def test_authenticated_user_can_view_own_activity_with_safe_presented_fields(client):
    user = make_user(email="activity@example.edu")
    authenticate_client(client, user)
    now = timezone.now()
    account_event = record_event(
        context=AuditContext.system(request_id=uuid4()),
        action=ACCOUNT_CREATED,
        outcome="SUCCESS",
        target_type="accounts.user",
        target_id=user.pk,
        occurred_at=now - timedelta(minutes=2),
        metadata={"internal_note": "must-not-leak"},
    )
    login_event = record_user_event(
        user=user,
        action=AUTH_LOGIN_SUCCESS,
        target_type="accounts.user",
        target_id=user.pk,
        occurred_at=now,
        metadata={"method": "password", "internal_note": "must-not-leak"},
    )

    response = client.get("/api/v1/me/activity")

    assert response.status_code == 200
    body = response.json()
    assert body["page"] == 1
    assert body["page_size"] == 20
    assert body["has_next"] is False
    assert [item["id"] for item in body["items"]] == [str(login_event.id), str(account_event.id)]
    item = body["items"][0]
    assert item["type"] == "auth.login"
    assert item["title"] == "Signed in to COMPASS"
    assert item["description"] == "You signed in to your account."
    occurred_at = datetime.fromisoformat(item["occurred_at"].replace("Z", "+00:00"))
    assert abs(occurred_at - login_event.occurred_at) < timedelta(milliseconds=1)
    assert "must-not-leak" not in response.content.decode()
    assert "request_id" not in item
    assert "ip_address" not in item
    assert "user_agent_summary" not in item
    assert "metadata" not in item
    assert "target_id" not in item


@pytest.mark.django_db
def test_security_activity_is_allowlisted_and_excludes_internal_or_unknown_actions(client):
    user = make_user(email="security@example.edu")
    authenticate_client(client, user)
    other = make_user(email="other-security@example.edu")
    now = timezone.now()
    owned_session = AuthSession.objects.create(
        user=user,
        token_digest="a" * 64,
        created_at=now - timedelta(days=1),
        last_used_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=1),
    )
    owned_trusted = TrustedSession.objects.create(
        user=user,
        token_digest="b" * 64,
        created_at=now - timedelta(days=1),
        last_used_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=1),
    )
    other_session = AuthSession.objects.create(
        user=other,
        token_digest="c" * 64,
        created_at=now - timedelta(days=1),
        last_used_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=1),
    )

    login_event = record_user_event(
        user=user,
        action=AUTH_LOGIN_SUCCESS,
        target_type="accounts.user",
        target_id=user.pk,
        occurred_at=now,
    )
    session_created = record_user_event(
        user=user,
        action=AUTH_SESSION_CREATED,
        target_type="auth.session",
        target_id=owned_session.pk,
        occurred_at=now - timedelta(minutes=1),
    )
    trusted_created = record_user_event(
        user=user,
        action=AUTH_TRUSTED_SESSION_CREATED,
        target_type="auth.trusted",
        target_id=owned_trusted.pk,
        occurred_at=now - timedelta(minutes=2),
    )
    failed_event = record_user_event(
        user=user,
        action=AUTH_LOGIN_FAILED,
        target_type="accounts.user",
        target_id=user.pk,
        outcome="DENIED",
        occurred_at=now - timedelta(minutes=3),
    )
    record_event(
        context=AuditContext.anonymous(request_id=uuid4()),
        action=AUTH_LOGIN_FAILED,
        outcome="DENIED",
        occurred_at=now - timedelta(minutes=4),
    )
    record_event(
        context=AuditContext.system(request_id=uuid4()),
        action=IDENTITY_POLICY_SYNCED,
        outcome="SUCCESS",
        occurred_at=now - timedelta(minutes=5),
    )
    record_user_event(
        user=user,
        action="internal.secret.action",
        target_type="accounts.user",
        target_id=user.pk,
        occurred_at=now - timedelta(minutes=6),
        metadata={"display_note": "not-visible"},
    )
    record_user_event(
        user=user,
        action=AUTH_SESSION_REVOKED,
        target_type="auth.session",
        target_id=other_session.pk,
        occurred_at=now - timedelta(minutes=7),
    )

    response = client.get("/api/v1/me/security-activity")

    assert response.status_code == 200
    items = response.json()["items"]
    assert [item["id"] for item in items] == [
        str(login_event.id),
        str(session_created.id),
        str(trusted_created.id),
        str(failed_event.id),
    ]
    assert items[2]["title"] == "Trusted browser added"
    assert "not-visible" not in response.content.decode()
    assert str(other_session.pk) not in response.content.decode()


@pytest.mark.django_db
def test_target_account_events_are_self_only_and_no_user_selector_is_supported(client):
    user = make_user(email="self@example.edu")
    other = make_user(email="other@example.edu")
    authenticate_client(client, user)
    now = timezone.now()
    own = record_event(
        context=AuditContext.system(),
        action=ACCOUNT_CREATED,
        outcome="SUCCESS",
        target_type="accounts.user",
        target_id=user.pk,
        occurred_at=now,
    )
    record_event(
        context=AuditContext.system(),
        action=ACCOUNT_CREATED,
        outcome="SUCCESS",
        target_type="accounts.user",
        target_id=other.pk,
        occurred_at=now - timedelta(minutes=1),
    )
    record_event(
        context=AuditContext.user(other),
        action=AUTH_LOGIN_SUCCESS,
        outcome="SUCCESS",
        target_type="accounts.user",
        target_id=user.pk,
        occurred_at=now - timedelta(minutes=2),
    )

    response = client.get(f"/api/v1/me/activity?user_id={other.pk}")

    assert response.status_code == 200
    assert [item["id"] for item in response.json()["items"]] == [str(own.id)]


@pytest.mark.django_db
def test_activity_pagination_is_bounded_and_stably_newest_first(client):
    user = make_user(email="pagination@example.edu")
    authenticate_client(client, user)
    base = timezone.now()
    events = [
        record_user_event(
            user=user,
            action=AUTH_LOGIN_SUCCESS,
            target_type="accounts.user",
            target_id=user.pk,
            occurred_at=base - timedelta(minutes=index),
        )
        for index in range(4)
    ]

    first = client.get("/api/v1/me/activity?page=1&page_size=2")
    second = client.get("/api/v1/me/activity?page=2&page_size=2")
    invalid = client.get("/api/v1/me/activity?page_size=51")

    assert first.status_code == second.status_code == 200
    assert first.json()["has_next"] is True
    assert second.json()["has_next"] is False
    first_ids = [item["id"] for item in first.json()["items"]]
    second_ids = [item["id"] for item in second.json()["items"]]
    assert first_ids == [str(events[0].id), str(events[1].id)]
    assert second_ids == [str(events[2].id), str(events[3].id)]
    assert set(first_ids).isdisjoint(second_ids)
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "invalid_pagination"


@pytest.mark.django_db
def test_security_activity_includes_totp_enrollment_and_logout_but_not_account_only_events(client):
    user = make_user(email="security-events@example.edu")
    authenticate_client(client, user)
    session = create_auth_session(user).session
    now = timezone.now()
    factor = TOTPFactor.objects.create(
        user=user,
        encrypted_secret="encrypted-test-secret",
        created_at=now,
        confirmed_at=now,
    )
    totp_event = record_user_event(
        user=user,
        action=AUTH_MFA_TOTP_ENROLLED,
        target_type="auth.totpfactor",
        target_id=factor.pk,
        occurred_at=now,
    )
    invalid_totp_event = record_user_event(
        user=user,
        action=AUTH_MFA_TOTP_ENROLLED,
        target_type="auth.totpfactor",
        target_id=uuid4(),
        occurred_at=now - timedelta(seconds=1),
    )
    logout_event = record_user_event(
        user=user,
        action=AUTH_LOGOUT,
        target_type="auth.session",
        target_id=session.pk,
        occurred_at=now - timedelta(minutes=1),
    )
    account_only = record_event(
        context=AuditContext.system(),
        action=ACCOUNT_CREATED,
        outcome="SUCCESS",
        target_type="accounts.user",
        target_id=user.pk,
        occurred_at=now - timedelta(minutes=2),
    )

    response = client.get("/api/v1/me/security-activity")

    assert response.status_code == 200
    ids = [item["id"] for item in response.json()["items"]]
    assert ids == [str(totp_event.id), str(logout_event.id)]
    assert str(invalid_totp_event.id) not in ids
    assert str(account_only.id) not in ids
