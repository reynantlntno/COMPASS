from datetime import timedelta
from io import StringIO
from unittest.mock import patch

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import Permission
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.db.models import UUIDField
from django.utils import timezone

from compass.accounts.models import (
    Capability,
    Designation,
    DesignationCapability,
    Role,
    RoleCapability,
    UserCapabilityOverride,
    UserDesignation,
)
from compass.accounts.policy import CAPABILITY_CODES
from compass.accounts.services import (
    effective_capabilities,
    set_user_capability_override,
)

User = get_user_model()


def sync_policy() -> None:
    call_command("sync_identity_policy", stdout=StringIO())


def make_user(*, role: Role | str = "STUDENT", email: str = "student@example.edu"):
    if isinstance(role, str):
        role = Role.objects.get(code=role)
    return User.objects.create_user(
        email=email,
        password="a-test-password",
        role=role,
        first_name="Test",
        last_name="User",
    )


@pytest.mark.django_db
def test_custom_user_uses_uuid_email_identity_and_no_django_permission_fields():
    assert settings.AUTH_USER_MODEL == "accounts.User"
    assert isinstance(User._meta.get_field("id"), UUIDField)
    assert User.USERNAME_FIELD == "email"
    assert User.REQUIRED_FIELDS == []
    assert not hasattr(User, "username")
    assert not hasattr(User, "groups")
    assert not hasattr(User, "user_permissions")
    assert not hasattr(User, "is_staff")
    assert not hasattr(User, "is_superuser")

    role = Role.objects.create(code="TEST_ROLE", name="Test role")
    user = User.objects.create_user(
        email="  Reynan@Example.edu ",
        password="correct horse battery staple",
        role=role,
        first_name="Reynan",
        last_name="Test",
    )

    assert user.email == "reynan@example.edu"
    assert user.get_username() == user.email
    assert user.check_password("correct horse battery staple")
    assert user.password != "correct horse battery staple"
    assert User.objects.get_by_natural_key("REYNAN@EXAMPLE.EDU") == user


@pytest.mark.django_db
def test_postgresql_expression_constraint_rejects_case_only_email_collision():
    role = Role.objects.create(code="TEST_ROLE", name="Test role")
    User.objects.bulk_create(
        [
            User(
                email="Reynan@Example.edu",
                password=make_password("password"),
                first_name="Reynan",
                last_name="Test",
                role=role,
            )
        ]
    )

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            User.objects.bulk_create(
                [
                    User(
                        email="reynan@example.edu",
                        password=make_password("password"),
                        first_name="Another",
                        last_name="Test",
                        role=role,
                    )
                ]
            )


@pytest.mark.django_db
def test_user_manager_requires_a_known_primary_role():
    with pytest.raises(ValueError, match="primary role is required"):
        User.objects.create_user(
            email="missing-role@example.edu",
            password="password",
            first_name="Missing",
            last_name="Role",
        )
    with pytest.raises(ValueError, match="unknown primary role"):
        User.objects.create_user(
            email="unknown-role@example.edu",
            password="password",
            role="NOT_A_ROLE",
            first_name="Unknown",
            last_name="Role",
        )


@pytest.mark.django_db
def test_policy_sync_is_idempotent_and_does_not_create_django_model_permissions():
    first_output = StringIO()
    call_command("sync_identity_policy", stdout=first_output)

    assert set(Role.objects.values_list("code", flat=True)) == {
        "IT_ADMIN",
        "COUNSELOR",
        "GUIDANCE_SERVICES_STAFF",
        "STUDENT",
    }
    assert set(Designation.objects.values_list("code", flat=True)) == {
        "HEAD_GUIDANCE_COUNSELOR",
        "DPO",
    }
    assert set(Capability.objects.values_list("code", flat=True)) == set(CAPABILITY_CODES)
    assert RoleCapability.objects.count() == 10
    assert DesignationCapability.objects.count() == 1
    assert Permission.objects.filter(content_type__app_label="accounts").count() == 0

    second_output = StringIO()
    call_command("sync_identity_policy", stdout=second_output)
    assert "roles created=0 updated=0" in second_output.getvalue()
    assert "designations created=0 updated=0" in second_output.getvalue()
    assert "capabilities created=0 updated=0" in second_output.getvalue()
    assert "role grants created=0" in second_output.getvalue()
    assert Role.objects.count() == 4
    assert Designation.objects.count() == 2
    assert Capability.objects.count() == 4
    assert RoleCapability.objects.count() == 10
    assert DesignationCapability.objects.count() == 1


@pytest.mark.django_db
def test_user_has_one_primary_role_and_can_hold_multiple_non_duplicate_designations():
    sync_policy()
    user = make_user()
    designations = list(Designation.objects.order_by("code"))
    UserDesignation.objects.create(user=user, designation=designations[0])
    UserDesignation.objects.create(user=user, designation=designations[1])

    assert set(user.designations.values_list("code", flat=True)) == {
        "DPO",
        "HEAD_GUIDANCE_COUNSELOR",
    }
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            UserDesignation.objects.create(user=user, designation=designations[0])


@pytest.mark.django_db
def test_effective_capabilities_combine_role_designation_and_overrides():
    sync_policy()
    user = make_user(role="COUNSELOR")
    head = Designation.objects.get(code="HEAD_GUIDANCE_COUNSELOR")
    manage = Capability.objects.get(code="accounts.manage")
    UserDesignation.objects.create(user=user, designation=head)
    DesignationCapability.objects.create(designation=head, capability=manage)

    assert effective_capabilities(user) == {
        "accounts.view",
        "accounts.manage",
        "organization.view",
        "organization.manage",
    }
    assert user.has_capability("accounts.view")
    assert user.has_capability("accounts.manage")

    revoke = set_user_capability_override(
        user=user,
        capability="accounts.manage",
        effect=UserCapabilityOverride.Effect.REVOKE,
        reason="Temporary separation of duties",
    )
    assert revoke.reason == "Temporary separation of duties"
    assert user.has_capability("accounts.view")
    assert user.has_capability("organization.view")
    assert user.has_capability("organization.manage")
    assert not user.has_capability("accounts.manage")

    grant = set_user_capability_override(
        user=user,
        capability=manage,
        effect=UserCapabilityOverride.Effect.GRANT,
        reason="Approved exception",
    )
    assert grant.pk == revoke.pk
    assert user.has_capability("accounts.manage")

    expired = set_user_capability_override(
        user=user,
        capability=manage,
        effect=UserCapabilityOverride.Effect.REVOKE,
        reason="Expired exception",
        expires_at=timezone.now() - timedelta(seconds=1),
    )
    assert expired.pk == revoke.pk
    assert user.has_capability("accounts.manage")
    assert not user.has_capability("accounts.future")

    unknown = Capability.objects.create(code="accounts.future", name="Unknown future action")
    RoleCapability.objects.create(role=user.role, capability=unknown)
    assert "accounts.future" not in effective_capabilities(user)
    assert not user.has_capability("accounts.future")

    user.is_active = False
    user.save(update_fields=["is_active", "updated_at"])
    assert effective_capabilities(user) == frozenset()
    assert not user.has_capability("accounts.view")


@pytest.mark.django_db
def test_override_requires_a_reason_and_known_capability():
    sync_policy()
    user = make_user()

    with pytest.raises(ValueError, match="reason is required"):
        set_user_capability_override(
            user=user,
            capability="accounts.view",
            effect=UserCapabilityOverride.Effect.GRANT,
            reason="   ",
        )
    with pytest.raises(ValueError, match="unknown capability"):
        set_user_capability_override(
            user=user,
            capability="not-in-policy",
            effect=UserCapabilityOverride.Effect.GRANT,
            reason="Should not authorize unknown policy",
        )


@pytest.mark.django_db
def test_create_it_admin_bootstraps_hashed_password_and_is_safe_on_repeat():
    sync_policy()
    output = StringIO()
    with patch(
        "compass.accounts.management.commands.create_it_admin.getpass.getpass",
        side_effect=["a-secure-password", "a-secure-password"],
    ):
        call_command(
            "create_it_admin",
            "--email",
            "IT.Admin@Example.edu",
            "--first-name",
            "IT",
            "--last-name",
            "Administrator",
            stdout=output,
        )

    user = User.objects.get()
    assert user.email == "it.admin@example.edu"
    assert user.role.code == "IT_ADMIN"
    assert user.check_password("a-secure-password")
    assert "a-secure-password" not in output.getvalue()

    with pytest.raises(CommandError, match="already exists"):
        call_command(
            "create_it_admin",
            "--email",
            "it.admin@example.edu",
            "--first-name",
            "Changed",
            "--last-name",
            "Name",
        )

    repeat_output = StringIO()
    call_command(
        "create_it_admin",
        "--email",
        "IT.ADMIN@EXAMPLE.EDU",
        "--first-name",
        "Changed",
        "--last-name",
        "Name",
        "--idempotent",
        stdout=repeat_output,
    )
    assert "no changes made" in repeat_output.getvalue()
    assert User.objects.count() == 1


@pytest.mark.django_db
def test_create_it_admin_requires_policy_sync():
    with pytest.raises(CommandError, match="sync_identity_policy first"):
        call_command(
            "create_it_admin",
            "--email",
            "it-admin@example.edu",
            "--first-name",
            "IT",
            "--last-name",
            "Admin",
        )


def test_django_admin_route_remains_unavailable(client):
    response = client.get("/admin/")
    assert response.status_code == 404
