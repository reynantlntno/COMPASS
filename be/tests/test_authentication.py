import json
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pyotp
import pytest
from cryptography.fernet import Fernet
from django.conf import settings
from django.db import transaction
from django.test import Client, override_settings
from django.utils import timezone

from compass.accounts.models import Role, User
from compass.audit.models import AuditEvent
from compass.authentication.abuse import (
    AuthenticationRateLimited,
    check_auth_rate_limit,
)
from compass.authentication.crypto import decrypt_totp_secret, encrypt_totp_secret
from compass.authentication.email_otp import (
    EmailOTPInvalid,
    EmailOTPResendTooSoon,
    consume_email_otp,
    issue_email_otp,
    resend_email_otp,
)
from compass.authentication.mfa import invalidate_recovery_codes, verify_totp_for_login
from compass.authentication.models import AuthSession, EmailOTPChallenge, RecoveryCode, TOTPFactor
from compass.authentication.sessions import (
    RecentMFARequired,
    require_recent_mfa,
    resolve_trusted_session,
)
from compass.common.rate_limit import RateLimitResult


def make_user(*, email="student@example.edu", password="correct-password", role_code="STUDENT"):
    role, _created = Role.objects.get_or_create(
        code=role_code,
        defaults={"name": role_code.replace("_", " ").title()},
    )
    return User.objects.create_user(
        email=email,
        password=password,
        role=role,
        first_name="Test",
        last_name="User",
    )


def csrf_headers(client):
    response = client.get("/api/v1/auth/csrf")
    assert response.status_code == 200
    return {"HTTP_X_CSRFTOKEN": response.json()["csrf_token"]}


def post_json(client, path, payload, *, headers=None):
    return client.post(
        path,
        data=json.dumps(payload),
        content_type="application/json",
        **(headers or {}),
    )


def login(client, *, email, password, trust_browser=False, headers=None):
    return post_json(
        client,
        "/api/v1/auth/login",
        {
            "email": email,
            "password": password,
            "trust_browser": trust_browser,
        },
        headers=headers if headers is not None else csrf_headers(client),
    )


class AllowLimiter:
    def __init__(self, *, blocked=False):
        self.blocked = blocked
        self.calls = []

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
def configure_auth_test_services(settings, monkeypatch):
    settings.AUTH_TOTP_ENCRYPTION_KEY = Fernet.generate_key().decode()
    monkeypatch.setattr(
        "compass.authentication.abuse.RedisRateLimiter.from_settings",
        lambda: AllowLimiter(),
    )


@pytest.mark.django_db
def test_password_login_is_generic_and_stores_only_a_session_digest():
    user = make_user(email="Case.User@example.edu")
    client = Client()

    success = login(client, email="case.user@EXAMPLE.EDU", password="correct-password")
    assert success.status_code == 200
    body = success.json()
    assert body["authenticated"] is True
    assert body["user"]["email"] == "case.user@example.edu"

    raw_token = client.cookies["compass_session"].value
    session = AuthSession.objects.get(pk=body["session_id"])
    assert session.user_id == user.pk
    assert session.token_digest != raw_token
    assert len(session.token_digest) == 64
    assert raw_token.encode() not in success.content
    assert raw_token not in str(list(AuditEvent.objects.values_list("metadata", flat=True)))

    current = client.get("/api/v1/auth/session")
    assert current.status_code == 200
    assert current.json()["session"]["id"] == str(session.pk)

    wrong_password = login(client, email="case.user@example.edu", password="wrong-password")
    unknown_email = login(client, email="unknown@example.edu", password="wrong-password")
    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json()["error"]["code"] == "authentication_failed"
    assert unknown_email.json()["error"]["code"] == "authentication_failed"
    assert AuditEvent.objects.filter(action="auth.login.failed", actor_user=user).exists()
    assert AuditEvent.objects.filter(action="auth.login.failed", actor_user__isnull=True).exists()


@pytest.mark.django_db
def test_inactive_account_cannot_login_or_use_an_existing_session():
    user = make_user(email="inactive@example.edu")
    client = Client()
    assert login(client, email=user.email, password="correct-password").status_code == 200
    raw_token = client.cookies["compass_session"].value

    user.is_active = False
    user.save(update_fields=["is_active", "updated_at"])

    client.cookies["compass_session"] = raw_token
    assert login(client, email=user.email, password="correct-password").status_code == 401
    assert client.get("/api/v1/auth/session").status_code == 401


@pytest.mark.django_db
def test_expired_session_cannot_authenticate():
    user = make_user(email="expired-session@example.edu")
    client = Client()
    assert login(client, email=user.email, password="correct-password").status_code == 200
    session = AuthSession.objects.get(user=user)
    expired_at = timezone.now() - timedelta(seconds=1)
    session.created_at = expired_at - timedelta(days=1)
    session.expires_at = expired_at
    session.save(update_fields=["created_at", "expires_at"])

    assert client.get("/api/v1/auth/session").status_code == 401


@pytest.mark.django_db
def test_cookie_csrf_flow_is_required_for_login_and_protected_mutations():
    user = make_user(email="csrf@example.edu")
    client = Client(enforce_csrf_checks=True)

    missing = login(
        client,
        email=user.email,
        password="correct-password",
        headers={},
    )
    assert missing.status_code == 403
    assert missing.json()["error"]["code"] == "csrf_failed"

    headers = csrf_headers(client)
    response = login(
        client,
        email=user.email,
        password="correct-password",
        headers=headers,
    )
    assert response.status_code == 200
    cookie = response.cookies["compass_session"]
    assert cookie["httponly"] is True
    assert cookie["samesite"] == "Lax"
    assert cookie["path"] == "/api/"

    logout_without_csrf = client.post("/api/v1/auth/logout")
    assert logout_without_csrf.status_code == 403
    logout = client.post("/api/v1/auth/logout", **csrf_headers(client))
    assert logout.status_code == 200
    assert logout.json()["revoked"] is True


@pytest.mark.django_db
def test_session_listing_and_revocation_primitives_are_explicit():
    user = make_user(email="sessions@example.edu")
    client = Client()
    first = login(client, email=user.email, password="correct-password")
    first_id = first.json()["session_id"]
    second = login(client, email=user.email, password="correct-password")
    second_id = second.json()["session_id"]

    listing = client.get("/api/v1/auth/sessions")
    assert listing.status_code == 200
    assert {item["id"] for item in listing.json()["sessions"]} == {first_id, second_id}
    assert all("token" not in item for item in listing.json()["sessions"])

    revoked = client.post("/api/v1/auth/sessions/revoke-others", **csrf_headers(client))
    assert revoked.status_code == 200
    assert revoked.json()["revoked_count"] == 1
    assert AuthSession.objects.get(pk=first_id).revoked_at is not None

    revoke_current = client.delete(f"/api/v1/auth/sessions/{second_id}", **csrf_headers(client))
    assert revoke_current.status_code == 200
    assert revoke_current.json()["revoked"] is True
    assert client.get("/api/v1/auth/session").status_code == 401


@pytest.mark.django_db
def test_totp_enrollment_is_pending_then_returns_one_time_recovery_codes():
    user = make_user(email="mfa@example.edu")
    client = Client()
    assert login(client, email=user.email, password="correct-password").status_code == 200

    setup = post_json(client, "/api/v1/auth/mfa/totp/setup", {}, headers=csrf_headers(client))
    assert setup.status_code == 200
    uri = setup.json()["provisioning_uri"]
    parsed = pyotp.parse_uri(uri)
    factor = TOTPFactor.objects.get(user=user)
    assert factor.confirmed_at is None
    assert factor.encrypted_secret != parsed.secret
    assert decrypt_totp_secret(factor.encrypted_secret) == parsed.secret

    confirmation = post_json(
        client,
        "/api/v1/auth/mfa/totp/confirm",
        {"code": parsed.now()},
        headers=csrf_headers(client),
    )
    assert confirmation.status_code == 200
    recovery_codes = confirmation.json()["recovery_codes"]
    assert confirmation.json()["enabled"] is True
    assert len(recovery_codes) == 10
    assert factor.__class__.objects.get(pk=factor.pk).confirmed_at is not None
    assert RecoveryCode.objects.filter(user=user).count() == 10
    hashes = list(RecoveryCode.objects.filter(user=user).values_list("code_hash", flat=True))
    for code in recovery_codes:
        assert all(code.replace("-", "") not in code_hash for code_hash in hashes)

    actions = set(AuditEvent.objects.filter(actor_user=user).values_list("action", flat=True))
    assert "auth.mfa.totp.setup.started" in actions
    assert "auth.mfa.totp.enrolled" in actions


@pytest.mark.django_db
def test_mfa_login_requires_challenge_and_consumes_recovery_code_once():
    user = make_user(email="challenge@example.edu")
    client = Client()
    assert login(client, email=user.email, password="correct-password").status_code == 200
    setup = post_json(client, "/api/v1/auth/mfa/totp/setup", {}, headers=csrf_headers(client))
    parsed = pyotp.parse_uri(setup.json()["provisioning_uri"])
    confirmed = post_json(
        client,
        "/api/v1/auth/mfa/totp/confirm",
        {"code": parsed.now()},
        headers=csrf_headers(client),
    )
    code = confirmed.json()["recovery_codes"][0]
    client.post("/api/v1/auth/logout", **csrf_headers(client))

    challenged = login(client, email=user.email, password="correct-password")
    assert challenged.status_code == 200
    assert challenged.json()["authenticated"] is False
    assert challenged.json()["mfa_required"] is True
    assert "compass_session" not in client.cookies or not client.cookies["compass_session"].value
    assert client.cookies["compass_login_challenge"]["httponly"] is True
    assert AuthSession.objects.filter(user=user, revoked_at__isnull=True).count() == 0

    completed = post_json(
        client,
        "/api/v1/auth/mfa/verify",
        {"method": "recovery", "code": code},
        headers=csrf_headers(client),
    )
    assert completed.status_code == 200
    assert completed.json()["authenticated"] is True
    assert AuthSession.objects.get(pk=completed.json()["session_id"]).mfa_verified_at is not None
    recovery = RecoveryCode.objects.get(user=user, used_at__isnull=False)
    assert recovery.used_at is not None

    client.post("/api/v1/auth/logout", **csrf_headers(client))
    login(client, email=user.email, password="correct-password")
    reused = post_json(
        client,
        "/api/v1/auth/mfa/verify",
        {"method": "recovery", "code": code},
        headers=csrf_headers(client),
    )
    assert reused.status_code == 400
    assert reused.json()["error"]["code"] == "mfa_failed"


@pytest.mark.django_db
def test_trusted_browser_satisfies_mfa_only_after_password_and_can_be_used_then_revoked():
    user = make_user(email="trusted@example.edu")
    client = Client()
    login(client, email=user.email, password="correct-password")
    setup = post_json(client, "/api/v1/auth/mfa/totp/setup", {}, headers=csrf_headers(client))
    parsed = pyotp.parse_uri(setup.json()["provisioning_uri"])
    confirmed = post_json(
        client,
        "/api/v1/auth/mfa/totp/confirm",
        {"code": parsed.now()},
        headers=csrf_headers(client),
    )
    recovery_code = confirmed.json()["recovery_codes"][0]
    client.post("/api/v1/auth/logout", **csrf_headers(client))

    login(client, email=user.email, password="correct-password", trust_browser=True)
    completed = post_json(
        client,
        "/api/v1/auth/mfa/verify",
        {"method": "recovery", "code": recovery_code},
        headers=csrf_headers(client),
    )
    assert completed.status_code == 200
    trusted_raw = client.cookies["compass_trusted"].value
    trusted = user.trusted_authentication_sessions.get()
    assert trusted.token_digest != trusted_raw
    trusted.expires_at = timezone.now() - timedelta(seconds=1)
    trusted.created_at = trusted.expires_at - timedelta(days=1)
    trusted.save(update_fields=["created_at", "expires_at"])
    assert resolve_trusted_session(trusted_raw) is None
    trusted.expires_at = timezone.now() + timedelta(days=1)
    trusted.save(update_fields=["expires_at"])
    client.post("/api/v1/auth/logout", **csrf_headers(client))

    trusted_login = login(client, email=user.email, password="correct-password")
    assert trusted_login.status_code == 200
    assert trusted_login.json()["authenticated"] is True
    assert (
        AuthSession.objects.get(pk=trusted_login.json()["session_id"]).mfa_verified_at is not None
    )

    revoke = client.delete(
        f"/api/v1/auth/trusted-sessions/{trusted.pk}",
        **csrf_headers(client),
    )
    assert revoke.status_code == 200
    assert trusted.__class__.objects.get(pk=trusted.pk).revoked_at is not None
    assert resolve_trusted_session(trusted_raw) is None


@pytest.mark.django_db
def test_totp_replay_is_rejected_by_time_step():
    user = make_user(email="replay@example.edu")
    fixed = timezone.make_aware(datetime(2026, 1, 1, 0, 0, 0))
    secret = pyotp.random_base32()
    factor = TOTPFactor.objects.create(
        user=user,
        encrypted_secret=encrypt_totp_secret(secret),
        created_at=fixed,
        confirmed_at=fixed,
    )
    code = pyotp.TOTP(secret).at(int(fixed.timestamp()))
    with transaction.atomic():
        first = verify_totp_for_login(user=user, code=code, now=fixed)
    with transaction.atomic():
        second = verify_totp_for_login(user=user, code=code, now=fixed)

    assert first.valid is True
    assert second.valid is False
    assert second.replayed is True
    assert TOTPFactor.objects.get(pk=factor.pk).last_verified_time_step is not None


@pytest.mark.django_db
def test_recent_mfa_helper_distinguishes_fresh_stale_and_missing_assertions():
    user = make_user(email="step-up@example.edu")
    session = AuthSession.objects.create(
        user=user,
        token_digest="a" * 64,
        created_at=timezone.now() - timedelta(minutes=2),
        last_used_at=timezone.now(),
        expires_at=timezone.now() + timedelta(days=1),
    )
    with pytest.raises(RecentMFARequired):
        require_recent_mfa(session)

    session.mfa_verified_at = timezone.now()
    session.save(update_fields=["mfa_verified_at"])
    require_recent_mfa(session)

    session.mfa_verified_at = timezone.now() - timedelta(hours=1)
    session.save(update_fields=["mfa_verified_at"])
    with pytest.raises(RecentMFARequired):
        require_recent_mfa(session)


@pytest.mark.django_db
def test_email_otp_is_hash_only_bounded_single_use_and_resendable(
    django_capture_on_commit_callbacks,
):
    user = make_user(email="otp@example.edu")
    limiter = AllowLimiter()
    now = timezone.now()
    with patch("compass.authentication.email_otp.deliver_email_otp.delay") as dispatch:
        with django_capture_on_commit_callbacks(execute=True):
            issue = issue_email_otp(
                email=user.email,
                purpose="security_challenge",
                user=user,
                limiter=limiter,
                dispatch=True,
                now=now,
            )
    first_code = dispatch.call_args.args[1]
    challenge = EmailOTPChallenge.objects.get(pk=issue.challenge.pk)
    assert first_code not in challenge.code_hash
    assert challenge.consumed_at is None

    consumed = consume_email_otp(
        challenge_id=challenge.pk,
        code=first_code,
        limiter=limiter,
        now=now,
    )
    assert consumed.consumed_at is not None
    with pytest.raises(EmailOTPInvalid):
        consume_email_otp(challenge_id=challenge.pk, code=first_code, limiter=limiter, now=now)

    fresh_issue = issue_email_otp(
        email=user.email,
        purpose="security_challenge",
        user=user,
        limiter=limiter,
        dispatch=False,
        now=now,
    )
    with pytest.raises(EmailOTPResendTooSoon):
        resend_email_otp(
            challenge_id=fresh_issue.challenge.pk,
            limiter=limiter,
            now=now + timedelta(seconds=1),
        )

    with pytest.raises(EmailOTPInvalid):
        resend_email_otp(
            challenge_id=challenge.pk,
            limiter=limiter,
            now=now + timedelta(seconds=61),
        )

    with patch("compass.authentication.email_otp.deliver_email_otp.delay") as resend_dispatch:
        with django_capture_on_commit_callbacks(execute=True):
            resend_email_otp(
                challenge_id=fresh_issue.challenge.pk,
                limiter=limiter,
                now=now + timedelta(seconds=61),
            )
    assert resend_dispatch.call_count == 1
    assert (
        resend_dispatch.call_args.args[1]
        not in EmailOTPChallenge.objects.get(pk=fresh_issue.challenge.pk).code_hash
    )


@pytest.mark.django_db
def test_email_otp_expiration_and_attempt_limit():
    user = make_user(email="otp-limits@example.edu")
    limiter = AllowLimiter()
    now = timezone.now()
    issue = issue_email_otp(
        email=user.email,
        purpose="security_challenge",
        user=user,
        limiter=limiter,
        dispatch=False,
        now=now,
    )

    with pytest.raises(EmailOTPInvalid):
        consume_email_otp(
            challenge_id=issue.challenge.pk,
            code="000000",
            limiter=limiter,
            now=now + timedelta(seconds=settings.AUTH_EMAIL_OTP_TTL_SECONDS + 1),
        )
    expired = EmailOTPChallenge.objects.get(pk=issue.challenge.pk)
    assert expired.failed_attempt_count == 0

    issue = issue_email_otp(
        email=user.email,
        purpose="security_challenge",
        user=user,
        limiter=limiter,
        dispatch=False,
        now=now,
    )
    with override_settings(AUTH_EMAIL_OTP_MAX_ATTEMPTS=2):
        for _attempt in range(2):
            with pytest.raises(EmailOTPInvalid):
                consume_email_otp(
                    challenge_id=issue.challenge.pk,
                    code="000000",
                    limiter=limiter,
                    now=now,
                )
        exhausted = EmailOTPChallenge.objects.get(pk=issue.challenge.pk)
        assert exhausted.failed_attempt_count == 2
        with pytest.raises(EmailOTPInvalid):
            consume_email_otp(
                challenge_id=issue.challenge.pk,
                code="000000",
                limiter=limiter,
                now=now,
            )
        assert EmailOTPChallenge.objects.get(pk=issue.challenge.pk).failed_attempt_count == 2


@pytest.mark.django_db
def test_recovery_code_invalidation_primitive_only_marks_usable_codes():
    user = make_user(email="recovery-invalidation@example.edu")
    now = timezone.now()
    used = RecoveryCode.objects.create(
        user=user,
        code_hash="used-hash",
        created_at=now,
        used_at=now,
    )
    usable = RecoveryCode.objects.create(user=user, code_hash="usable-hash", created_at=now)

    assert invalidate_recovery_codes(user_id=user.pk, now=now + timedelta(seconds=1)) == 1
    used.refresh_from_db()
    usable.refresh_from_db()
    assert used.invalidated_at is None
    assert usable.invalidated_at == now + timedelta(seconds=1)


def test_authentication_rate_limits_use_shared_redis_limiter_shapes():
    limiter = AllowLimiter()
    check_auth_rate_limit(
        "login",
        ip_address="203.0.113.10",
        identifier="person@example.edu",
        limiter=limiter,
    )
    assert {policy.name for policy, _subject in limiter.calls} == {
        "auth.login.ip",
        "auth.login.identifier",
        "auth.login.combination",
    }

    with pytest.raises(AuthenticationRateLimited):
        check_auth_rate_limit(
            "totp",
            ip_address="203.0.113.10",
            user_id="user-id",
            limiter=AllowLimiter(blocked=True),
        )


@pytest.mark.django_db
def test_turnstile_required_login_uses_server_side_verifier_without_persisting_token():
    user = make_user(email="turnstile@example.edu")
    fake_verifier = SimpleNamespace(
        verify=lambda token, **kwargs: SimpleNamespace(success=token == "valid-token")
    )
    with override_settings(
        AUTH_TURNSTILE_LOGIN_REQUIRED=True,
        TURNSTILE_ENABLED=True,
        TURNSTILE_SECRET_KEY="server-only-secret",
    ):
        with patch(
            "compass.authentication.abuse.TurnstileVerifier.from_settings",
            return_value=fake_verifier,
        ):
            from compass.authentication.services import authenticate_login

            rejected = authenticate_login(
                request=Client().get("/api/v1/auth/csrf").wsgi_request,
                email=user.email,
                password="correct-password",
                turnstile_token="invalid-token",
                limiter=AllowLimiter(),
            )
            assert rejected.status == "failed"
            accepted = authenticate_login(
                request=Client().get("/api/v1/auth/csrf").wsgi_request,
                email=user.email,
                password="correct-password",
                turnstile_token="valid-token",
                limiter=AllowLimiter(),
            )
            assert accepted.status == "success"
    assert not EmailOTPChallenge.objects.filter(email="valid-token").exists()
