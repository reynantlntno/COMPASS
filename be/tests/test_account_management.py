import json
from datetime import timedelta
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from django.core.management import call_command
from django.test import Client
from django.utils import timezone

from compass.accounts.models import (
    Capability,
    Designation,
    Role,
    User,
    UserCapabilityOverride,
    UserDesignation,
)
from compass.audit.models import AuditEvent
from compass.authentication.crypto import encrypt_totp_secret
from compass.authentication.models import (
    AuthSession,
    EmailOTPChallenge,
    LoginChallenge,
    RecoveryCode,
    TOTPFactor,
    TrustedSession,
)
from compass.authentication.sessions import (
    create_auth_session,
    create_login_challenge,
    create_trusted_session,
)


def sync_policy() -> None:
    call_command("sync_identity_policy", verbosity=0)


def make_user(*, email: str, role: str = "STUDENT", active: bool = True) -> User:
    role_record = Role.objects.get(code=role)
    return User.objects.create_user(
        email=email,
        password="a-test-password",
        role=role_record,
        first_name="Test",
        last_name="User",
        is_active=active,
    )


def make_admin_client(*, email: str = "manager@example.edu") -> tuple[Client, User, AuthSession]:
    admin = make_user(email=email, role="IT_ADMIN")
    now = timezone.now()
    issued = create_auth_session(admin, mfa_verified_at=now, now=now)
    client = Client()
    client.cookies["compass_session"] = issued.token
    return client, admin, issued.session


def csrf_headers(client: Client) -> dict[str, str]:
    response = client.get("/api/v1/auth/csrf")
    assert response.status_code == 200
    return {"HTTP_X_CSRFTOKEN": response.json()["csrf_token"]}


def post_json(client: Client, path: str, payload: dict, *, headers=None):
    return client.post(
        path,
        data=json.dumps(payload),
        content_type="application/json",
        **(headers or {}),
    )


@pytest.fixture(autouse=True)
def configure_security(settings, monkeypatch):
    settings.AUTH_TOTP_ENCRYPTION_KEY = Fernet.generate_key().decode()
    monkeypatch.setattr(
        "compass.authentication.abuse.RedisRateLimiter.from_settings",
        lambda: _AllowLimiter(),
    )


class _AllowLimiter:
    def consume_with_failure_policy(self, policy, subject):
        from compass.common.rate_limit import RateLimitResult

        return RateLimitResult(
            allowed=True,
            count=1,
            limit=policy.limit,
            remaining=policy.limit - 1,
            retry_after_seconds=1,
        )


@pytest.mark.django_db
def test_account_management_requires_manage_not_accounts_view_and_requires_recent_mfa_for_writes():
    sync_policy()
    student = make_user(email="student@example.edu")
    student_session = create_auth_session(student)
    student_client = Client()
    student_client.cookies["compass_session"] = student_session.token

    assert student_client.get("/api/v1/accounts").status_code == 403

    manager_client, _admin, _session = make_admin_client()
    target = make_user(email="target@example.edu")
    without_step_up = create_auth_session(_admin)
    manager_client.cookies["compass_session"] = without_step_up.token
    response = post_json(
        manager_client,
        f"/api/v1/accounts/{target.pk}/disable",
        {},
        headers=csrf_headers(manager_client),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "recent_mfa_required"


@pytest.mark.django_db
def test_manager_can_list_create_and_inspect_accounts_without_sensitive_fields():
    sync_policy()
    client, _admin, _session = make_admin_client()
    response = post_json(
        client,
        "/api/v1/accounts",
        {
            "email": "  New.User@Example.edu ",
            "first_name": "New",
            "last_name": "User",
            "role": "COUNSELOR",
        },
        headers=csrf_headers(client),
    )
    assert response.status_code == 201
    body = response.json()
    created = User.objects.get(email="new.user@example.edu")
    assert body["id"] == str(created.pk)
    assert body["email"] == "new.user@example.edu"
    assert body["password_configured"] is False
    assert body["mfa_enabled"] is False
    assert not hasattr(created, "password_hash")
    assert "password" not in body
    assert "profile_photo_object_key" not in body
    assert AuditEvent.objects.filter(
        action="account.created",
        actor_user=_admin,
        target_id=str(created.pk),
    ).exists()
    created_session = create_auth_session(created)
    created_client = Client()
    created_client.cookies["compass_session"] = created_session.token
    activity = created_client.get("/api/v1/me/activity")
    assert activity.status_code == 200
    assert any(item["type"] == "account.created" for item in activity.json()["items"])

    listing = client.get("/api/v1/accounts?page=1&page_size=1&search=NEW.USER")
    assert listing.status_code == 200
    assert len(listing.json()["items"]) == 1
    assert listing.json()["items"][0]["email"] == "new.user@example.edu"
    assert listing.json()["items"][0]["role"] == "COUNSELOR"
    assert "password_configured" not in listing.json()["items"][0]

    forbidden = post_json(
        client,
        "/api/v1/accounts",
        {
            "email": "bad@example.edu",
            "first_name": "Bad",
            "last_name": "Payload",
            "role": "STUDENT",
            "password": "never-accepted",
        },
        headers=csrf_headers(client),
    )
    assert forbidden.status_code == 422
    assert not User.objects.filter(email="bad@example.edu").exists()


@pytest.mark.django_db
def test_account_listing_filters_and_pagination_are_bounded():
    sync_policy()
    client, _admin, _session = make_admin_client()
    make_user(email="active-counselor@example.edu", role="COUNSELOR")
    inactive = make_user(email="inactive-student@example.edu", active=False)
    dpo = make_user(email="dpo-student@example.edu")
    UserDesignation.objects.create(user=dpo, designation=Designation.objects.get(code="DPO"))

    page = client.get("/api/v1/accounts?page=1&page_size=1")
    assert page.status_code == 200
    assert len(page.json()["items"]) == 1
    assert page.json()["has_next"] is True

    role = client.get("/api/v1/accounts?role=COUNSELOR")
    assert role.status_code == 200
    assert [item["role"] for item in role.json()["items"]] == ["COUNSELOR"]

    active = client.get("/api/v1/accounts?is_active=false")
    assert active.status_code == 200
    assert [item["id"] for item in active.json()["items"]] == [str(inactive.pk)]

    designation = client.get("/api/v1/accounts?designation=DPO")
    assert designation.status_code == 200
    assert [item["id"] for item in designation.json()["items"]] == [str(dpo.pk)]

    too_large = client.get("/api/v1/accounts?page_size=51")
    assert too_large.status_code == 422
    invalid_page = client.get("/api/v1/accounts?page=0")
    assert invalid_page.status_code == 422


@pytest.mark.django_db
def test_account_creation_rejects_duplicate_email_and_noncanonical_role():
    sync_policy()
    client, _admin, _session = make_admin_client()
    payload = {
        "email": "duplicate@example.edu",
        "first_name": "Duplicate",
        "last_name": "User",
        "role": "STUDENT",
    }
    first = post_json(client, "/api/v1/accounts", payload, headers=csrf_headers(client))
    duplicate = post_json(
        client,
        "/api/v1/accounts",
        {**payload, "email": "DUPLICATE@example.edu"},
        headers=csrf_headers(client),
    )
    unknown_role = post_json(
        client,
        "/api/v1/accounts",
        {**payload, "email": "unknown-role@example.edu", "role": "NOT_CANONICAL"},
        headers=csrf_headers(client),
    )
    assert first.status_code == 201
    assert duplicate.status_code == 409
    assert unknown_role.status_code == 422


@pytest.mark.django_db
def test_identity_email_change_invalidates_target_security_state_and_audits_fields_only():
    sync_policy()
    client, admin, _session = make_admin_client()
    target = make_user(email="old@example.edu")
    now = timezone.now()
    target_session = create_auth_session(target, now=now).session
    trusted = create_trusted_session(target, now=now).session
    challenge = create_login_challenge(
        target,
        allowed_methods=["totp"],
        trust_browser=False,
        now=now,
    ).challenge
    email_challenge = EmailOTPChallenge.objects.create(
        user=target,
        email=target.email,
        purpose="security_challenge",
        code_hash="hash",
        created_at=now,
        expires_at=now + timedelta(minutes=5),
        last_sent_at=now,
    )

    response = client.patch(
        f"/api/v1/accounts/{target.pk}/identity",
        data=json.dumps({"email": " New@Example.edu ", "first_name": "Renamed"}),
        content_type="application/json",
        **csrf_headers(client),
    )
    assert response.status_code == 200
    target.refresh_from_db()
    assert target.email == "new@example.edu"
    assert target.first_name == "Renamed"
    assert AuthSession.objects.get(pk=target_session.pk).revoked_at is not None
    assert TrustedSession.objects.get(pk=trusted.pk).revoked_at is not None
    assert LoginChallenge.objects.get(pk=challenge.pk).consumed_at is not None
    assert EmailOTPChallenge.objects.get(pk=email_challenge.pk).consumed_at is not None
    assert target.has_usable_password()
    event = AuditEvent.objects.get(action="account.updated", target_id=str(target.pk))
    assert event.actor_user_id == admin.pk
    assert event.metadata == {"changed_fields": ["email", "first_name"]}
    assert "old@example.edu" not in str(event.metadata)
    assert "new@example.edu" not in str(event.metadata)


@pytest.mark.django_db
def test_disable_enable_revokes_state_preserves_mfa_and_is_idempotent():
    sync_policy()
    client, _admin, _session = make_admin_client()
    target = make_user(email="disable@example.edu")
    now = timezone.now()
    session = create_auth_session(target, now=now).session
    trusted = create_trusted_session(target, now=now).session
    challenge = create_login_challenge(
        target,
        allowed_methods=["totp"],
        trust_browser=False,
        now=now,
    ).challenge
    factor = TOTPFactor.objects.create(
        user=target,
        encrypted_secret=encrypt_totp_secret("JBSWY3DPEHPK3PXP"),
        created_at=now,
        confirmed_at=now,
    )

    path = f"/api/v1/accounts/{target.pk}/disable"
    first = post_json(client, path, {}, headers=csrf_headers(client))
    second = post_json(client, path, {}, headers=csrf_headers(client))
    assert first.status_code == second.status_code == 200
    target.refresh_from_db()
    assert target.is_active is False
    assert AuthSession.objects.get(pk=session.pk).revoked_at is not None
    assert TrustedSession.objects.get(pk=trusted.pk).revoked_at is not None
    assert LoginChallenge.objects.get(pk=challenge.pk).consumed_at is not None
    assert TOTPFactor.objects.get(pk=factor.pk).disabled_at is None
    assert (
        AuditEvent.objects.filter(action="account.disabled", target_id=str(target.pk)).count() == 1
    )

    enabled = post_json(
        client,
        f"/api/v1/accounts/{target.pk}/enable",
        {},
        headers=csrf_headers(client),
    )
    assert enabled.status_code == 200
    assert enabled.json()["is_active"] is True
    assert AuthSession.objects.get(pk=session.pk).revoked_at is not None
    assert (
        AuditEvent.objects.filter(action="account.enabled", target_id=str(target.pk)).count() == 1
    )


@pytest.mark.django_db
def test_role_designation_and_override_mutations_update_authority_and_invalidate_sessions():
    sync_policy()
    client, _admin, _session = make_admin_client()
    target = make_user(email="authority@example.edu", role="COUNSELOR")
    target_session = create_auth_session(target).session

    designation = post_json(
        client,
        f"/api/v1/accounts/{target.pk}/designations/DPO",
        {},
        headers=csrf_headers(client),
    )
    assert designation.status_code == 200
    assert designation.json()["designations"] == ["DPO"]
    assert UserDesignation.objects.filter(user=target, designation__code="DPO").exists()
    assert AuthSession.objects.get(pk=target_session.pk).revoked_at is not None

    override = client.put(
        f"/api/v1/accounts/{target.pk}/capability-overrides/accounts.manage",
        data=json.dumps(
            {
                "effect": "GRANT",
                "reason": "Temporary operational coverage",
                "expires_at": (timezone.now() + timedelta(days=1)).isoformat(),
            }
        ),
        content_type="application/json",
        **csrf_headers(client),
    )
    assert override.status_code == 200
    assert override.json()["effect"] == "GRANT"
    target.refresh_from_db()
    assert target.has_capability("accounts.manage")
    assert UserCapabilityOverride.objects.get(user=target).created_by_id == _admin.pk

    role = client.put(
        f"/api/v1/accounts/{target.pk}/role",
        data=json.dumps({"role": "GUIDANCE_SERVICES_STAFF"}),
        content_type="application/json",
        **csrf_headers(client),
    )
    assert role.status_code == 200
    target.refresh_from_db()
    assert target.role.code == "GUIDANCE_SERVICES_STAFF"
    assert target.has_capability("accounts.manage")

    removed = client.delete(
        f"/api/v1/accounts/{target.pk}/capability-overrides/accounts.manage",
        **csrf_headers(client),
    )
    assert removed.status_code == 200
    assert removed.json() == {"removed": True}
    target.refresh_from_db()
    assert not target.has_capability("accounts.manage")


@pytest.mark.django_db
def test_last_manager_and_self_target_safety_are_enforced():
    from compass.account_management import services as management_services

    sync_policy()
    client, admin, _session = make_admin_client()
    target = make_user(email="other-admin@example.edu", role="IT_ADMIN")

    final = post_json(
        client,
        f"/api/v1/accounts/{admin.pk}/disable",
        {},
        headers=csrf_headers(client),
    )
    assert final.status_code == 403
    assert final.json()["error"]["code"] == "self_target_forbidden"

    demote = client.put(
        f"/api/v1/accounts/{target.pk}/role",
        data=json.dumps({"role": "STUDENT"}),
        content_type="application/json",
        **csrf_headers(client),
    )
    assert demote.status_code == 200
    assert AuditEvent.objects.filter(
        action="account.role.changed", target_id=str(target.pk)
    ).exists()

    target.refresh_from_db()
    with patch.object(management_services, "_active_manager_count", return_value=0):
        blocked = client.put(
            f"/api/v1/accounts/{target.pk}/role",
            data=json.dumps({"role": "COUNSELOR"}),
            content_type="application/json",
            **csrf_headers(client),
        )
    assert blocked.status_code == 409
    target.refresh_from_db()
    assert target.role.code == "STUDENT"


@pytest.mark.django_db
def test_administrative_mfa_reset_never_returns_mfa_material():
    sync_policy()
    client, admin, _session = make_admin_client()
    target = make_user(email="mfa-reset@example.edu")
    now = timezone.now()
    factor = TOTPFactor.objects.create(
        user=target,
        encrypted_secret=encrypt_totp_secret("JBSWY3DPEHPK3PXP"),
        created_at=now,
        confirmed_at=now,
    )
    recovery = RecoveryCode.objects.create(user=target, code_hash="hashed-recovery")
    target_session = create_auth_session(target, now=now).session
    target_trusted = create_trusted_session(target, now=now).session
    challenge = create_login_challenge(
        target,
        allowed_methods=["totp"],
        trust_browser=False,
        now=now,
    ).challenge

    response = post_json(
        client,
        f"/api/v1/accounts/{target.pk}/security/reset-mfa",
        {},
        headers=csrf_headers(client),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["reset"] is True
    assert "recovery_codes" not in body
    assert "provisioning_uri" not in body
    assert "secret" not in response.content.decode().lower()
    assert TOTPFactor.objects.get(pk=factor.pk).disabled_at is not None
    assert RecoveryCode.objects.get(pk=recovery.pk).invalidated_at is not None
    assert AuthSession.objects.get(pk=target_session.pk).revoked_at is not None
    assert TrustedSession.objects.get(pk=target_trusted.pk).revoked_at is not None
    assert LoginChallenge.objects.get(pk=challenge.pk).consumed_at is not None
    event = AuditEvent.objects.get(action="account.mfa.reset", target_id=str(target.pk))
    assert event.actor_user_id == admin.pk
    assert event.metadata == {}


@pytest.mark.django_db
def test_administrative_session_revocation_uses_authentication_primitives_and_target_activity():
    sync_policy()
    client, admin, _session = make_admin_client()
    target = make_user(email="security-target@example.edu")
    now = timezone.now()
    auth = create_auth_session(target, now=now).session
    trusted = create_trusted_session(target, now=now).session

    sessions = post_json(
        client,
        f"/api/v1/accounts/{target.pk}/security/revoke-sessions",
        {},
        headers=csrf_headers(client),
    )
    trusted_sessions = post_json(
        client,
        f"/api/v1/accounts/{target.pk}/security/revoke-trusted-sessions",
        {},
        headers=csrf_headers(client),
    )
    assert sessions.status_code == trusted_sessions.status_code == 200
    assert sessions.json() == {"revoked_count": 1}
    assert trusted_sessions.json() == {"revoked_count": 1}
    assert AuthSession.objects.get(pk=auth.pk).revoked_at is not None
    assert TrustedSession.objects.get(pk=trusted.pk).revoked_at is not None
    assert all(
        event.actor_user_id == admin.pk
        for event in AuditEvent.objects.filter(
            action__in=["auth.session.revoked", "auth.trusted.session.revoked"],
            target_id__in=[str(auth.pk), str(trusted.pk)],
        )
    )

    target_session = create_auth_session(target, now=timezone.now())
    target_client = Client()
    target_client.cookies["compass_session"] = target_session.token
    activity = target_client.get("/api/v1/me/activity")
    assert activity.status_code == 200
    activity_types = {item["type"] for item in activity.json()["items"]}
    assert {"auth.session.revoked", "auth.trusted.session.revoked"} <= activity_types


@pytest.mark.django_db
def test_effective_manage_override_authorizes_without_role_shortcut():
    sync_policy()
    actor = make_user(email="override-manager@example.edu", role="COUNSELOR")
    capability = Capability.objects.get(code="accounts.manage")
    UserCapabilityOverride.objects.create(
        user=actor,
        capability=capability,
        effect=UserCapabilityOverride.Effect.GRANT,
        reason="Approved temporary manager",
    )
    now = timezone.now()
    issued = create_auth_session(actor, mfa_verified_at=now, now=now)
    client = Client()
    client.cookies["compass_session"] = issued.token
    response = client.get("/api/v1/accounts")
    assert response.status_code == 200
