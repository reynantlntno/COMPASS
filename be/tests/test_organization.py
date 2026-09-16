from __future__ import annotations

import json

import pytest
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
from compass.audit.context import AuditContext
from compass.audit.models import AuditEvent
from compass.authentication.sessions import create_auth_session
from compass.organization.models import (
    Campus,
    College,
    CounselorResponsibility,
    StaffSupervision,
    StudentAffiliation,
)
from compass.organization.services import (
    OrganizationConflict,
    effective_responsibility_colleges,
    resolve_default_counselor_for_student,
    set_counselor_responsibility,
    set_staff_supervisor,
    set_student_affiliation,
)


def sync_policy() -> None:
    call_command("sync_identity_policy", verbosity=0)


def make_user(email: str, role: str, *, active: bool = True) -> User:
    return User.objects.create_user(
        email=email,
        password="a-test-password",
        role=Role.objects.get(code=role),
        first_name="Test",
        last_name="User",
        is_active=active,
    )


def context(actor: User) -> AuditContext:
    return AuditContext.user(actor)


def auth_client(user: User, *, recent_mfa: bool = True) -> Client:
    now = timezone.now()
    issued = create_auth_session(
        user,
        now=now,
        mfa_verified_at=now if recent_mfa else None,
    )
    client = Client()
    client.cookies["compass_session"] = issued.token
    return client


def csrf(client: Client) -> dict[str, str]:
    response = client.get("/api/v1/auth/csrf")
    assert response.status_code == 200
    return {"HTTP_X_CSRFTOKEN": response.json()["csrf_token"]}


@pytest.mark.django_db
def test_policy_grants_organization_capabilities_and_revoke_still_wins():
    sync_policy()
    admin = make_user("admin@example.edu", "IT_ADMIN")
    counselor = make_user("counselor@example.edu", "COUNSELOR")
    student = make_user("student@example.edu", "STUDENT")
    head = Designation.objects.get(code="HEAD_GUIDANCE_COUNSELOR")
    UserDesignation.objects.create(user=counselor, designation=head)

    assert admin.has_capability("organization.manage")
    assert student.has_capability("organization.view")
    assert counselor.has_capability("organization.manage")

    UserCapabilityOverride.objects.create(
        user=counselor,
        capability=Capability.objects.get(code="organization.manage"),
        effect="REVOKE",
        reason="separation",
    )
    assert not counselor.has_capability("organization.manage")


@pytest.mark.django_db
def test_effective_scope_head_and_gss_inheritance_are_dynamic_not_capability_inheritance():
    sync_policy()
    campus = Campus.objects.create(code="MAIN", name="Main")
    college_a = College.objects.create(campus=campus, code="A", name="A")
    college_b = College.objects.create(campus=campus, code="B", name="B")
    counselor = make_user("c@example.edu", "COUNSELOR")
    staff = make_user("gss@example.edu", "GUIDANCE_SERVICES_STAFF")

    set_counselor_responsibility(
        college_id=college_a.pk,
        counselor_id=counselor.pk,
        context=context(counselor),
    )
    set_staff_supervisor(
        staff_id=staff.pk,
        supervisor_id=counselor.pk,
        context=context(counselor),
    )
    assert {item.pk for item in effective_responsibility_colleges(counselor)} == {college_a.pk}
    assert {item.pk for item in effective_responsibility_colleges(staff)} == {college_a.pk}

    CounselorResponsibility.objects.create(college=college_b, counselor=counselor)
    assert {item.pk for item in effective_responsibility_colleges(staff)} == {
        college_a.pk,
        college_b.pk,
    }

    UserDesignation.objects.create(
        user=counselor,
        designation=Designation.objects.get(code="HEAD_GUIDANCE_COUNSELOR"),
    )
    assert {item.pk for item in effective_responsibility_colleges(counselor)} == {
        college_a.pk,
        college_b.pk,
    }
    assert {item.pk for item in effective_responsibility_colleges(staff)} == {
        college_a.pk,
        college_b.pk,
    }
    assert not staff.has_capability("organization.manage")


@pytest.mark.django_db
def test_default_routing_prefers_college_then_head_and_reports_head_ambiguity():
    sync_policy()
    campus = Campus.objects.create(code="M", name="Main")
    college = College.objects.create(campus=campus, code="C", name="College")
    student = make_user("s@example.edu", "STUDENT")
    counselor = make_user("c@example.edu", "COUNSELOR")
    head_one = make_user("h1@example.edu", "COUNSELOR")
    head_two = make_user("h2@example.edu", "COUNSELOR")
    head = Designation.objects.get(code="HEAD_GUIDANCE_COUNSELOR")
    UserDesignation.objects.create(user=head_one, designation=head)

    set_student_affiliation(
        student_id=student.pk,
        college_id=college.pk,
        context=context(head_one),
    )
    result = resolve_default_counselor_for_student(student)
    assert result.counselor == head_one
    assert result.source == "HEAD_GUIDANCE_FALLBACK"

    set_counselor_responsibility(
        college_id=college.pk,
        counselor_id=counselor.pk,
        context=context(head_one),
    )
    result = resolve_default_counselor_for_student(student)
    assert result.counselor == counselor
    assert result.source == "COLLEGE_RESPONSIBILITY"

    counselor.is_active = False
    counselor.save(update_fields=["is_active", "updated_at"])
    assert resolve_default_counselor_for_student(student).counselor == head_one

    UserDesignation.objects.create(user=head_two, designation=head)
    result = resolve_default_counselor_for_student(student)
    assert result.counselor is None
    assert result.reason == "AMBIGUOUS_HEAD_CONFIGURATION"


@pytest.mark.django_db
def test_disabled_supervisor_keeps_relationship_but_staff_operational_scope_is_empty():
    sync_policy()
    campus = Campus.objects.create(code="M", name="Main")
    college = College.objects.create(campus=campus, code="C", name="College")
    counselor = make_user("c@example.edu", "COUNSELOR")
    staff = make_user("staff@example.edu", "GUIDANCE_SERVICES_STAFF")
    CounselorResponsibility.objects.create(college=college, counselor=counselor)
    StaffSupervision.objects.create(staff=staff, supervisor=counselor)

    counselor.is_active = False
    counselor.save(update_fields=["is_active", "updated_at"])
    assert StaffSupervision.objects.filter(staff=staff).exists()
    assert effective_responsibility_colleges(staff) == ()


@pytest.mark.django_db
def test_assignment_noop_does_not_create_fake_audit_event():
    sync_policy()
    actor = make_user("admin@example.edu", "IT_ADMIN")
    campus = Campus.objects.create(code="M", name="Main")
    college = College.objects.create(campus=campus, code="C", name="College")
    student = make_user("s@example.edu", "STUDENT")

    set_student_affiliation(
        student_id=student.pk,
        college_id=college.pk,
        context=context(actor),
    )
    count = AuditEvent.objects.filter(action__startswith="organization.student_affiliation").count()
    set_student_affiliation(
        student_id=student.pk,
        college_id=college.pk,
        context=context(actor),
    )
    assert StudentAffiliation.objects.filter(student=student).count() == 1
    assert (
        AuditEvent.objects.filter(action__startswith="organization.student_affiliation").count()
        == count
    )


@pytest.mark.django_db
def test_role_changes_are_blocked_until_organization_relationship_is_removed():
    sync_policy()
    admin = make_user("admin@example.edu", "IT_ADMIN")
    student = make_user("s@example.edu", "STUDENT")
    campus = Campus.objects.create(code="M", name="Main")
    college = College.objects.create(campus=campus, code="C", name="College")
    StudentAffiliation.objects.create(student=student, college=college, assigned_by=admin)
    client = auth_client(admin)
    headers = csrf(client)

    blocked = client.put(
        f"/api/v1/accounts/{student.pk}/role",
        data=json.dumps({"role": "COUNSELOR"}),
        content_type="application/json",
        **headers,
    )
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "organization_relationship_conflict"

    StudentAffiliation.objects.filter(student=student).delete()
    allowed = client.put(
        f"/api/v1/accounts/{student.pk}/role",
        data=json.dumps({"role": "COUNSELOR"}),
        content_type="application/json",
        **headers,
    )
    assert allowed.status_code == 200


@pytest.mark.django_db
def test_structure_disable_refuses_active_children_and_current_assignments():
    sync_policy()
    actor = make_user("admin@example.edu", "IT_ADMIN")
    campus = Campus.objects.create(code="M", name="Main")
    college = College.objects.create(campus=campus, code="C", name="College")
    student = make_user("s@example.edu", "STUDENT")
    StudentAffiliation.objects.create(student=student, college=college, assigned_by=actor)

    from compass.organization.services import set_campus_active, set_college_active

    with pytest.raises(OrganizationConflict):
        set_campus_active(campus_id=campus.pk, is_active=False, context=context(actor))
    with pytest.raises(OrganizationConflict):
        set_college_active(college_id=college.pk, is_active=False, context=context(actor))


@pytest.mark.django_db
def test_manager_api_uses_capability_and_recent_mfa_not_role_shortcut():
    sync_policy()
    counselor = make_user("head@example.edu", "COUNSELOR")
    UserDesignation.objects.create(
        user=counselor,
        designation=Designation.objects.get(code="HEAD_GUIDANCE_COUNSELOR"),
    )

    stale = auth_client(counselor, recent_mfa=False)
    response = stale.post(
        "/api/v1/organization/campuses",
        data=json.dumps({"code": "M", "name": "Main"}),
        content_type="application/json",
        **csrf(stale),
    )
    assert response.status_code == 403

    fresh = auth_client(counselor)
    created = fresh.post(
        "/api/v1/organization/campuses",
        data=json.dumps({"code": "m", "name": "Main"}),
        content_type="application/json",
        **csrf(fresh),
    )
    assert created.status_code == 201
    assert created.json()["code"] == "M"

    UserCapabilityOverride.objects.create(
        user=counselor,
        capability=Capability.objects.get(code="organization.manage"),
        effect="REVOKE",
        reason="separation",
    )
    denied = fresh.post(
        "/api/v1/organization/campuses",
        data=json.dumps({"code": "N", "name": "North"}),
        content_type="application/json",
        **csrf(fresh),
    )
    assert denied.status_code == 403
