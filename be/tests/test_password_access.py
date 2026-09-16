"""Focused tests for self-service initial password setup and recovery."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from django.contrib.auth.hashers import make_password
from django.db import close_old_connections, connection
from django.test import Client, override_settings
from django.utils import timezone

from compass.accounts.models import Role, User
from compass.activity.projections import get_security_activity
from compass.audit.models import AuditEvent
from compass.authentication.actions import AUTH_PASSWORD_INITIAL_SET, AUTH_PASSWORD_RESET
from compass.authentication.models import (
    AuthSession,
    EmailOTPChallenge,
    EmailOTPPurpose,
    LoginChallenge,
    RecoveryCode,
    TOTPFactor,
    TrustedSession,
)
from compass.authentication.password_access import (
    PASSWORD_CHALLENGE_INVALID_MESSAGE,
    PasswordChallengeInvalid,
    confirm_password_access,
    request_password_access,
)
from compass.authentication.sessions import (
    create_auth_session,
    create_login_challenge,
    create_trusted_session,
)
from compass.common.rate_limit import RateLimitResult

NEW_PASSWORD = "river lanterns across campus"
RESET_PASSWORD = "quiet gardens beside the library"
CURRENT_PASSWORD = "the original compass password"


class AllowLimiter:
    def __init__(self, *, blocked: bool = False):
        self.blocked = blocked
        self.calls: list[tuple[object, str]] = []

    def consume_with_failure_policy(self, policy, subject):
        self.calls.append((policy, subject))
        return RateLimitResult(
            allowed=not self.blocked,
            count=policy.limit + 1 if self.blocked else 1,
            limit=policy.limit,
            remaining=0 if self.blocked else policy.limit - 1,
            retry_after_seconds=23,
        )


@pytest.fixture(autouse=True)
def configure_password_access_services(settings, monkeypatch):
    settings.AUTH_TOTP_ENCRYPTION_KEY = Fernet.generate_key().decode()
    limiter = AllowLimiter()
    monkeypatch.setattr(
        "compass.authentication.abuse.RedisRateLimiter.from_settings",
        lambda: limiter,
    )
    return limiter


def make_user(*, email: str = "student@example.edu", password: str | None = CURRENT_PASSWORD):
    role, _created = Role.objects.get_or_create(
        code="STUDENT",
        defaults={"name": "Student"},
    )
    return User.objects.create_user(
        email=email,
        password=password,
        role=role,
        first_name="Test",
        last_name="User",
    )


def post_json(client: Client, path: str, payload: dict[str, object], *, csrf: bool = True):
    headers = {}
    if csrf:
        csrf_response = client.get("/api/v1/auth/csrf")
        assert csrf_response.status_code == 200
        headers["HTTP_X_CSRFTOKEN"] = csrf_response.json()["csrf_token"]
    return client.post(
        path,
        data=json.dumps(payload),
        content_type="application/json",
        **headers,
    )


def issue_via_api(client: Client, email: str, code: str = "123456"):
    with (
        patch("compass.authentication.email_otp._new_code", return_value=code),
        patch("compass.authentication.email_otp.deliver_email_otp.delay") as delivery,
    ):
        response = post_json(
            client,
            "/api/v1/auth/password/request",
            {"email": email},
        )
    return response, delivery


def issue_direct(email: str, *, code: str = "123456"):
    with (
        patch("compass.authentication.email_otp._new_code", return_value=code),
        patch("compass.authentication.email_otp.deliver_email_otp.delay"),
    ):
        result = request_password_access(email=email)
    return result.challenge


@pytest.mark.django_db(transaction=True)
def test_request_known_active_account_creates_hash_only_dispatched_recovery_challenge():
    user = make_user(email="Case.User@Example.edu")
    client = Client()

    response, delivery = issue_via_api(client, "case.user@EXAMPLE.EDU")

    assert response.status_code == 202
    body = response.json()
    assert set(body) == {"challenge_id", "expires_at", "message"}
    assert body["message"] == "If the account is eligible, a security code has been sent."
    assert {"user_id", "is_active", "password_configured"}.isdisjoint(body)

    challenge = EmailOTPChallenge.objects.get(pk=body["challenge_id"])
    assert challenge.user_id == user.pk
    assert challenge.email == "case.user@example.edu"
    assert challenge.purpose == EmailOTPPurpose.RECOVERY
    assert challenge.consumed_at is None
    assert "123456" not in challenge.code_hash
    assert challenge.code_hash != "123456"
    delivery.assert_called_once_with(str(challenge.pk), "123456")


@pytest.mark.django_db(transaction=True)
def test_request_unknown_and_disabled_accounts_have_same_public_shape_without_delivery():
    disabled = make_user(email="disabled@example.edu")
    disabled.is_active = False
    disabled.save(update_fields=["is_active"])
    client = Client()

    unknown_response, unknown_delivery = issue_via_api(client, "unknown@example.edu", code="111111")
    disabled_response, disabled_delivery = issue_via_api(
        client,
        "disabled@example.edu",
        code="222222",
    )

    assert unknown_response.status_code == disabled_response.status_code == 202
    assert set(unknown_response.json()) == set(disabled_response.json())
    assert unknown_response.json()["message"] == disabled_response.json()["message"]
    assert unknown_delivery.call_count == 0
    assert disabled_delivery.call_count == 0

    unknown_challenge = EmailOTPChallenge.objects.get(pk=unknown_response.json()["challenge_id"])
    disabled_challenge = EmailOTPChallenge.objects.get(pk=disabled_response.json()["challenge_id"])
    assert unknown_challenge.user_id is None
    assert disabled_challenge.user_id is None
    assert unknown_challenge.email == "unknown@example.edu"
    assert disabled_challenge.email == "disabled@example.edu"
    assert unknown_challenge.purpose == disabled_challenge.purpose == EmailOTPPurpose.RECOVERY


@pytest.mark.django_db(transaction=True)
def test_request_initial_setup_account_uses_the_same_real_flow():
    user = make_user(email="new.user@example.edu", password=None)
    client = Client()

    response, delivery = issue_via_api(client, user.email)

    assert response.status_code == 202
    challenge = EmailOTPChallenge.objects.get(pk=response.json()["challenge_id"])
    assert challenge.user_id == user.pk
    assert not user.has_usable_password()
    delivery.assert_called_once()


@pytest.mark.django_db(transaction=True)
def test_request_replaces_only_outstanding_recovery_challenge():
    user = make_user(email="replace@example.edu")
    client = Client()
    first_response, _first_delivery = issue_via_api(client, user.email, code="111111")
    second_response, _second_delivery = issue_via_api(client, user.email, code="222222")

    first = EmailOTPChallenge.objects.get(pk=first_response.json()["challenge_id"])
    second = EmailOTPChallenge.objects.get(pk=second_response.json()["challenge_id"])
    assert first.pk != second.pk
    assert first.consumed_at is not None
    assert second.consumed_at is None

    stale = post_json(
        client,
        "/api/v1/auth/password/confirm",
        {
            "challenge_id": str(first.pk),
            "code": "111111",
            "new_password": NEW_PASSWORD,
        },
    )
    assert stale.status_code == 400
    assert stale.json()["error"]["code"] == "password_challenge_invalid"
    assert not user.check_password(NEW_PASSWORD)


@pytest.mark.django_db(transaction=True)
def test_password_request_rate_limit_and_turnstile_use_existing_safe_controls(monkeypatch):
    user = make_user(email="controls@example.edu")
    client = Client()
    blocked = AllowLimiter(blocked=True)
    monkeypatch.setattr(
        "compass.authentication.abuse.RedisRateLimiter.from_settings",
        lambda: blocked,
    )

    limited = issue_via_api(client, user.email)[0]
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "rate_limited"
    assert not EmailOTPChallenge.objects.filter(email=user.email).exists()

    monkeypatch.setattr(
        "compass.authentication.abuse.RedisRateLimiter.from_settings",
        lambda: AllowLimiter(),
    )
    with override_settings(AUTH_TURNSTILE_EMAIL_OTP_REQUIRED=True, TURNSTILE_ENABLED=False):
        rejected = post_json(
            client,
            "/api/v1/auth/password/request",
            {"email": user.email},
        )
    assert rejected.status_code == 403
    assert rejected.json()["error"]["code"] == "security_verification_failed"
    assert not EmailOTPChallenge.objects.filter(email=user.email).exists()


@pytest.mark.django_db(transaction=True)
def test_confirm_initial_password_sets_django_password_without_auto_login():
    user = make_user(email="initial@example.edu", password=None)
    client = Client()
    response, _delivery = issue_via_api(client, user.email)

    confirmed = post_json(
        client,
        "/api/v1/auth/password/confirm",
        {
            "challenge_id": response.json()["challenge_id"],
            "code": "123456",
            "new_password": NEW_PASSWORD,
        },
    )

    assert confirmed.status_code == 200
    assert confirmed.json() == {"password_set": True}
    user.refresh_from_db()
    assert user.has_usable_password()
    assert user.check_password(NEW_PASSWORD)
    assert AuthSession.objects.filter(user=user).count() == 0
    assert AuditEvent.objects.filter(
        action=AUTH_PASSWORD_INITIAL_SET,
        actor_user=user,
        target_type="accounts.user",
        target_id=str(user.pk),
        metadata={"method": "email_otp"},
    ).exists()

    login = post_json(
        client,
        "/api/v1/auth/login",
        {"email": user.email, "password": NEW_PASSWORD},
    )
    assert login.status_code == 200
    assert login.json()["authenticated"] is True


@pytest.mark.django_db(transaction=True)
def test_confirm_password_policy_failure_does_not_burn_valid_otp():
    user = make_user(email="policy@example.edu", password=None)
    client = Client()
    response, _delivery = issue_via_api(client, user.email)
    challenge_id = response.json()["challenge_id"]

    rejected = post_json(
        client,
        "/api/v1/auth/password/confirm",
        {
            "challenge_id": challenge_id,
            "code": "123456",
            "new_password": "abc",
        },
    )
    assert rejected.status_code == 422
    assert rejected.json()["error"]["code"] == "password_policy_failed"
    assert "abc" not in json.dumps(rejected.json())
    challenge = EmailOTPChallenge.objects.get(pk=challenge_id)
    assert challenge.consumed_at is None
    assert not user.has_usable_password()
    assert not AuditEvent.objects.filter(action=AUTH_PASSWORD_INITIAL_SET).exists()

    accepted = post_json(
        client,
        "/api/v1/auth/password/confirm",
        {
            "challenge_id": challenge_id,
            "code": "123456",
            "new_password": NEW_PASSWORD,
        },
    )
    assert accepted.status_code == 200
    assert User.objects.get(pk=user.pk).check_password(NEW_PASSWORD)


@pytest.mark.django_db(transaction=True)
def test_confirm_rejects_malformed_expired_and_exhausted_codes_safely():
    user = make_user(email="otp-state@example.edu", password=None)
    limiter = AllowLimiter()
    challenge = issue_direct(user.email)

    with override_settings(AUTH_EMAIL_OTP_MAX_ATTEMPTS=2):
        for code in ("not-six-digits", "000000"):
            with pytest.raises(PasswordChallengeInvalid):
                confirm_password_access(
                    challenge_id=challenge.pk,
                    code=code,
                    new_password=NEW_PASSWORD,
                    limiter=limiter,
                )
        with pytest.raises(PasswordChallengeInvalid):
            confirm_password_access(
                challenge_id=challenge.pk,
                code="123456",
                new_password=NEW_PASSWORD,
                limiter=limiter,
            )

    challenge.refresh_from_db()
    user.refresh_from_db()
    assert challenge.failed_attempt_count == 2
    assert challenge.consumed_at is None
    assert not user.has_usable_password()

    expired = issue_direct(user.email)
    with pytest.raises(PasswordChallengeInvalid):
        confirm_password_access(
            challenge_id=expired.pk,
            code="123456",
            new_password=NEW_PASSWORD,
            limiter=limiter,
            now=expired.expires_at + timedelta(seconds=1),
        )
    expired.refresh_from_db()
    assert expired.failed_attempt_count == 0
    assert expired.consumed_at is None


@pytest.mark.django_db(transaction=True)
def test_confirm_password_reset_rejects_exact_reuse_and_audits_reset():
    user = make_user(email="reset@example.edu")
    client = Client()
    response, _delivery = issue_via_api(client, user.email)
    challenge_id = response.json()["challenge_id"]

    reused = post_json(
        client,
        "/api/v1/auth/password/confirm",
        {
            "challenge_id": challenge_id,
            "code": "123456",
            "new_password": CURRENT_PASSWORD,
        },
    )
    assert reused.status_code == 422
    assert reused.json()["error"]["code"] == "password_policy_failed"
    assert reused.json()["error"]["details"][0]["type"] == "password_reuse"
    assert EmailOTPChallenge.objects.get(pk=challenge_id).consumed_at is None

    confirmed = post_json(
        client,
        "/api/v1/auth/password/confirm",
        {
            "challenge_id": challenge_id,
            "code": "123456",
            "new_password": RESET_PASSWORD,
        },
    )
    assert confirmed.status_code == 200
    user.refresh_from_db()
    assert not user.check_password(CURRENT_PASSWORD)
    assert user.check_password(RESET_PASSWORD)
    assert AuditEvent.objects.filter(
        action=AUTH_PASSWORD_RESET,
        actor_user=user,
        target_type="accounts.user",
        target_id=str(user.pk),
        metadata={"method": "email_otp"},
    ).exists()
    assert CURRENT_PASSWORD not in json.dumps(
        list(AuditEvent.objects.values_list("metadata", flat=True))
    )


@pytest.mark.django_db(transaction=True)
def test_reset_revokes_reusable_state_preserves_mfa_and_projects_safe_activity():
    user = make_user(email="state@example.edu")
    now = timezone.now()
    create_auth_session(user, now=now)
    create_trusted_session(user, now=now)
    login_challenge = create_login_challenge(
        user,
        allowed_methods=["totp", "recovery"],
        trust_browser=False,
        now=now,
    ).challenge
    factor = TOTPFactor.objects.create(
        user=user,
        encrypted_secret="encrypted-test-secret",
        confirmed_at=now,
    )
    recovery_code = RecoveryCode.objects.create(
        user=user,
        code_hash=make_password("recovery-code"),
    )
    client = Client()
    response, _delivery = issue_via_api(client, user.email)

    confirmed = post_json(
        client,
        "/api/v1/auth/password/confirm",
        {
            "challenge_id": response.json()["challenge_id"],
            "code": "123456",
            "new_password": RESET_PASSWORD,
        },
    )
    assert confirmed.status_code == 200
    assert AuthSession.objects.filter(user=user, revoked_at__isnull=True).count() == 0
    assert TrustedSession.objects.filter(user=user, revoked_at__isnull=True).count() == 0
    assert LoginChallenge.objects.get(pk=login_challenge.pk).consumed_at is not None
    assert TOTPFactor.objects.get(pk=factor.pk).disabled_at is None
    assert RecoveryCode.objects.get(pk=recovery_code.pk).used_at is None
    assert RecoveryCode.objects.get(pk=recovery_code.pk).invalidated_at is None

    activity = get_security_activity(User.objects.get(pk=user.pk))
    items = [item.as_dict() for item in activity.items]
    assert any(
        item["type"] == AUTH_PASSWORD_RESET
        and item["title"] == "Password reset"
        and item["description"]
        == "Your COMPASS account password was changed using account recovery."
        for item in items
    )
    assert all(
        "metadata" not in item and "challenge" not in json.dumps(item, default=str)
        for item in items
    )


@pytest.mark.django_db(transaction=True)
def test_decoy_disabled_and_email_changed_challenges_cannot_set_password():
    unknown = Client()
    decoy_response, _delivery = issue_via_api(unknown, "nobody@example.edu", code="111111")
    decoy_confirm = post_json(
        unknown,
        "/api/v1/auth/password/confirm",
        {
            "challenge_id": decoy_response.json()["challenge_id"],
            "code": "111111",
            "new_password": NEW_PASSWORD,
        },
    )
    assert decoy_confirm.status_code == 400
    assert decoy_confirm.json()["error"]["message"] == PASSWORD_CHALLENGE_INVALID_MESSAGE

    disabled = make_user(email="disable-after-issue@example.edu", password=None)
    disabled_client = Client()
    disabled_response, _delivery = issue_via_api(disabled_client, disabled.email)
    disabled.is_active = False
    disabled.save(update_fields=["is_active"])
    disabled_confirm = post_json(
        disabled_client,
        "/api/v1/auth/password/confirm",
        {
            "challenge_id": disabled_response.json()["challenge_id"],
            "code": "123456",
            "new_password": NEW_PASSWORD,
        },
    )
    assert disabled_confirm.status_code == 400
    assert not User.objects.get(pk=disabled.pk).has_usable_password()

    changed = make_user(email="old-email@example.edu", password=None)
    changed_client = Client()
    changed_response, _delivery = issue_via_api(changed_client, changed.email)
    changed.email = "new-email@example.edu"
    changed.save(update_fields=["email", "updated_at"])
    changed_confirm = post_json(
        changed_client,
        "/api/v1/auth/password/confirm",
        {
            "challenge_id": changed_response.json()["challenge_id"],
            "code": "123456",
            "new_password": NEW_PASSWORD,
        },
    )
    assert changed_confirm.status_code == 400
    assert not User.objects.get(pk=changed.pk).has_usable_password()


@pytest.mark.django_db(transaction=True)
def test_same_valid_otp_can_mutate_password_at_most_once_concurrently():
    user = make_user(email="concurrent@example.edu", password=None)
    challenge = issue_direct(user.email)

    def attempt():
        close_old_connections()
        try:
            return confirm_password_access(
                challenge_id=challenge.pk,
                code="123456",
                new_password=NEW_PASSWORD,
            )
        except Exception as exc:  # noqa: BLE001 - one result is intentionally the safe failure
            return exc
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: attempt(), range(2)))

    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert sum(isinstance(result, PasswordChallengeInvalid) for result in results) == 1
    user.refresh_from_db()
    assert user.check_password(NEW_PASSWORD)
    assert EmailOTPChallenge.objects.get(pk=challenge.pk).consumed_at is not None
