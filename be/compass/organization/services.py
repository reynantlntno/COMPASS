"""Transactional Organization services and canonical default-responsibility resolvers."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from django.db import IntegrityError, transaction
from django.db.models import Q

from compass.accounts.models import User
from compass.audit.actions import (
    ORGANIZATION_CAMPUS_CREATED,
    ORGANIZATION_CAMPUS_DISABLED,
    ORGANIZATION_CAMPUS_ENABLED,
    ORGANIZATION_CAMPUS_UPDATED,
    ORGANIZATION_COLLEGE_CREATED,
    ORGANIZATION_COLLEGE_DISABLED,
    ORGANIZATION_COLLEGE_ENABLED,
    ORGANIZATION_COLLEGE_UPDATED,
    ORGANIZATION_COUNSELOR_RESPONSIBILITY_ASSIGNED,
    ORGANIZATION_COUNSELOR_RESPONSIBILITY_CHANGED,
    ORGANIZATION_COUNSELOR_RESPONSIBILITY_REMOVED,
    ORGANIZATION_STAFF_SUPERVISION_ASSIGNED,
    ORGANIZATION_STAFF_SUPERVISION_CHANGED,
    ORGANIZATION_STAFF_SUPERVISION_REMOVED,
    ORGANIZATION_STUDENT_AFFILIATION_ASSIGNED,
    ORGANIZATION_STUDENT_AFFILIATION_CHANGED,
    ORGANIZATION_STUDENT_AFFILIATION_REMOVED,
)
from compass.audit.context import AuditContext
from compass.audit.models import AuditOutcome
from compass.audit.services import record_event
from compass.organization.models import (
    Campus,
    College,
    CounselorResponsibility,
    StaffSupervision,
    StudentAffiliation,
    normalize_code,
)

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 50
HEAD_DESIGNATION = "HEAD_GUIDANCE_COUNSELOR"


class OrganizationError(RuntimeError):
    pass


class OrganizationNotFound(OrganizationError):
    pass


class InvalidOrganizationInput(OrganizationError):
    pass


class OrganizationConflict(OrganizationError):
    pass


class OrganizationRoleTransitionConflict(OrganizationConflict):
    pass


@dataclass(frozen=True, slots=True)
class DefaultCounselorResolution:
    counselor: User | None
    source: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class PeoplePage:
    items: tuple[User, ...]
    page: int
    page_size: int
    has_next: bool


def _clean_name(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidOrganizationInput("name is required")
    cleaned = value.strip()
    if len(cleaned) > 160:
        raise InvalidOrganizationInput("name is too long")
    return cleaned


def _clean_code(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidOrganizationInput("code is required")
    cleaned = normalize_code(value)
    if len(cleaned) > 32:
        raise InvalidOrganizationInput("code is too long")
    return cleaned


def _actor(context: AuditContext) -> User | None:
    actor = context.actor_user
    return actor if isinstance(actor, User) else None


def _active_colleges():
    return College.objects.filter(is_active=True, campus__is_active=True).select_related("campus")


def effective_responsibility_colleges(user: User) -> tuple[College, ...]:
    """Resolve default responsibility only; this is not a resource-access decision."""
    if not getattr(user, "pk", None) or not user.is_active:
        return ()
    if user.role.code == "COUNSELOR":
        if user.designations.filter(code=HEAD_DESIGNATION).exists():
            return tuple(_active_colleges().order_by("campus__code", "code"))
        return tuple(
            _active_colleges()
            .filter(counselor_responsibility__counselor_id=user.pk)
            .order_by("campus__code", "code")
        )
    if user.role.code == "GUIDANCE_SERVICES_STAFF":
        supervision = (
            StaffSupervision.objects.select_related("supervisor__role")
            .filter(staff_id=user.pk)
            .first()
        )
        if supervision is None or not supervision.supervisor.is_active:
            return ()
        if supervision.supervisor.role.code != "COUNSELOR":
            return ()
        return effective_responsibility_colleges(supervision.supervisor)
    return ()


def resolve_default_counselor_for_student(student: User) -> DefaultCounselorResolution:
    if not getattr(student, "pk", None) or not student.is_active or student.role.code != "STUDENT":
        return DefaultCounselorResolution(None, "UNRESOLVED", "INVALID_STUDENT")
    affiliation = (
        StudentAffiliation.objects.select_related("college__campus")
        .filter(student_id=student.pk)
        .first()
    )
    if affiliation is None:
        return DefaultCounselorResolution(None, "UNRESOLVED", "NO_AFFILIATION")
    college = affiliation.college
    if not college.is_active or not college.campus.is_active:
        return DefaultCounselorResolution(None, "UNRESOLVED", "INACTIVE_ORGANIZATION")
    responsibility = (
        CounselorResponsibility.objects.select_related("counselor__role")
        .filter(college_id=college.pk)
        .first()
    )
    if (
        responsibility is not None
        and responsibility.counselor.is_active
        and responsibility.counselor.role.code == "COUNSELOR"
    ):
        return DefaultCounselorResolution(
            responsibility.counselor, "COLLEGE_RESPONSIBILITY"
        )
    heads = list(
        User.objects.filter(
            is_active=True,
            role__code="COUNSELOR",
            designation_assignments__designation__code=HEAD_DESIGNATION,
        )
        .select_related("role")
        .distinct()[:2]
    )
    if len(heads) == 1:
        return DefaultCounselorResolution(heads[0], "HEAD_GUIDANCE_FALLBACK")
    if not heads:
        return DefaultCounselorResolution(None, "UNRESOLVED", "NO_HEAD_FALLBACK")
    return DefaultCounselorResolution(None, "UNRESOLVED", "AMBIGUOUS_HEAD_CONFIGURATION")


def validate_role_transition(*, user: User, new_role_code: str) -> None:
    if user.role.code == new_role_code:
        return
    if user.role.code == "COUNSELOR":
        if CounselorResponsibility.objects.filter(counselor_id=user.pk).exists():
            raise OrganizationRoleTransitionConflict(
                "Remove or reassign the counselor's college responsibilities before changing role."
            )
        if StaffSupervision.objects.filter(supervisor_id=user.pk).exists():
            raise OrganizationRoleTransitionConflict(
                "Remove or reassign supervised Guidance Services Staff before changing role."
            )
    if user.role.code == "GUIDANCE_SERVICES_STAFF" and StaffSupervision.objects.filter(
        staff_id=user.pk
    ).exists():
        raise OrganizationRoleTransitionConflict(
            "Remove the staff supervision relationship before changing role."
        )
    if user.role.code == "STUDENT" and StudentAffiliation.objects.filter(student_id=user.pk).exists():
        raise OrganizationRoleTransitionConflict(
            "Remove the student's organizational affiliation before changing role."
        )


def list_campuses(*, is_active: bool | None = None, search: str | None = None) -> tuple[Campus, ...]:
    qs = Campus.objects.all().order_by("code")
    if is_active is not None:
        qs = qs.filter(is_active=is_active)
    if search and search.strip():
        term = search.strip()[:160]
        qs = qs.filter(Q(code__icontains=term) | Q(name__icontains=term))
    return tuple(qs)


def get_campus(campus_id: UUID) -> Campus:
    campus = Campus.objects.filter(pk=campus_id).first()
    if campus is None:
        raise OrganizationNotFound("The requested campus was not found.")
    return campus


def create_campus(*, code: str, name: str, context: AuditContext) -> Campus:
    with transaction.atomic():
        try:
            campus = Campus.objects.create(code=_clean_code(code), name=_clean_name(name))
        except IntegrityError as exc:
            raise OrganizationConflict("A campus with this code already exists.") from exc
        record_event(
            context=context,
            action=ORGANIZATION_CAMPUS_CREATED,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.campus",
            target_id=campus.pk,
            metadata={"code": campus.code},
        )
        return campus


def update_campus(*, campus_id: UUID, changes: dict[str, object], context: AuditContext) -> Campus:
    with transaction.atomic():
        campus = Campus.objects.select_for_update().filter(pk=campus_id).first()
        if campus is None:
            raise OrganizationNotFound("The requested campus was not found.")
        normalized = {}
        if "code" in changes:
            normalized["code"] = _clean_code(changes["code"])
        if "name" in changes:
            normalized["name"] = _clean_name(changes["name"])
        changed = [key for key, value in normalized.items() if getattr(campus, key) != value]
        if not changed:
            return campus
        for key in changed:
            setattr(campus, key, normalized[key])
        try:
            campus.save(update_fields=[*changed, "updated_at"])
        except IntegrityError as exc:
            raise OrganizationConflict("A campus with this code already exists.") from exc
        record_event(
            context=context,
            action=ORGANIZATION_CAMPUS_UPDATED,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.campus",
            target_id=campus.pk,
            metadata={"changed_fields": changed},
        )
        return campus


def set_campus_active(*, campus_id: UUID, is_active: bool, context: AuditContext) -> Campus:
    with transaction.atomic():
        campus = Campus.objects.select_for_update().filter(pk=campus_id).first()
        if campus is None:
            raise OrganizationNotFound("The requested campus was not found.")
        if campus.is_active == is_active:
            return campus
        if not is_active and College.objects.filter(campus_id=campus.pk, is_active=True).exists():
            raise OrganizationConflict("Disable active Colleges before disabling this Campus.")
        campus.is_active = is_active
        campus.save(update_fields=["is_active", "updated_at"])
        record_event(
            context=context,
            action=ORGANIZATION_CAMPUS_ENABLED if is_active else ORGANIZATION_CAMPUS_DISABLED,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.campus",
            target_id=campus.pk,
            metadata={},
        )
        return campus


def list_colleges(*, campus_id: UUID | None = None, is_active: bool | None = None, search: str | None = None) -> tuple[College, ...]:
    qs = College.objects.select_related("campus").order_by("campus__code", "code")
    if campus_id is not None:
        qs = qs.filter(campus_id=campus_id)
    if is_active is not None:
        qs = qs.filter(is_active=is_active)
    if search and search.strip():
        term = search.strip()[:160]
        qs = qs.filter(Q(code__icontains=term) | Q(name__icontains=term))
    return tuple(qs)


def get_college(college_id: UUID) -> College:
    college = College.objects.select_related("campus").filter(pk=college_id).first()
    if college is None:
        raise OrganizationNotFound("The requested college was not found.")
    return college


def create_college(*, campus_id: UUID, code: str, name: str, context: AuditContext) -> College:
    with transaction.atomic():
        campus = Campus.objects.select_for_update().filter(pk=campus_id).first()
        if campus is None:
            raise OrganizationNotFound("The requested campus was not found.")
        if not campus.is_active:
            raise OrganizationConflict("A College cannot be created under an inactive Campus.")
        try:
            college = College.objects.create(
                campus=campus,
                code=_clean_code(code),
                name=_clean_name(name),
            )
        except IntegrityError as exc:
            raise OrganizationConflict(
                "A College with this code already exists in the Campus."
            ) from exc
        record_event(
            context=context,
            action=ORGANIZATION_COLLEGE_CREATED,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.college",
            target_id=college.pk,
            metadata={"campus_id": str(campus.pk), "code": college.code},
        )
        return college


def update_college(*, college_id: UUID, changes: dict[str, object], context: AuditContext) -> College:
    with transaction.atomic():
        college = (
            College.objects.select_for_update()
            .select_related("campus")
            .filter(pk=college_id)
            .first()
        )
        if college is None:
            raise OrganizationNotFound("The requested college was not found.")
        normalized = {}
        if "code" in changes:
            normalized["code"] = _clean_code(changes["code"])
        if "name" in changes:
            normalized["name"] = _clean_name(changes["name"])
        changed = [key for key, value in normalized.items() if getattr(college, key) != value]
        if not changed:
            return college
        for key in changed:
            setattr(college, key, normalized[key])
        try:
            college.save(update_fields=[*changed, "updated_at"])
        except IntegrityError as exc:
            raise OrganizationConflict(
                "A College with this code already exists in the Campus."
            ) from exc
        record_event(
            context=context,
            action=ORGANIZATION_COLLEGE_UPDATED,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.college",
            target_id=college.pk,
            metadata={"changed_fields": changed},
        )
        return college


def set_college_active(*, college_id: UUID, is_active: bool, context: AuditContext) -> College:
    with transaction.atomic():
        college = (
            College.objects.select_for_update()
            .select_related("campus")
            .filter(pk=college_id)
            .first()
        )
        if college is None:
            raise OrganizationNotFound("The requested college was not found.")
        if college.is_active == is_active:
            return college
        if is_active and not college.campus.is_active:
            raise OrganizationConflict("Enable the parent Campus before enabling this College.")
        if not is_active and (
            StudentAffiliation.objects.filter(college_id=college.pk).exists()
            or CounselorResponsibility.objects.filter(college_id=college.pk).exists()
        ):
            raise OrganizationConflict(
                "Remove or reassign current organizational relationships before disabling this College."
            )
        college.is_active = is_active
        college.save(update_fields=["is_active", "updated_at"])
        record_event(
            context=context,
            action=ORGANIZATION_COLLEGE_ENABLED if is_active else ORGANIZATION_COLLEGE_DISABLED,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.college",
            target_id=college.pk,
            metadata={},
        )
        return college


def _lock_user_with_role(
    user_id: UUID,
    role_code: str,
    label: str,
    *,
    require_active: bool,
) -> User:
    user = User.objects.select_for_update().select_related("role").filter(pk=user_id).first()
    if user is None:
        raise OrganizationNotFound(f"The requested {label} was not found.")
    if user.role.code != role_code or (require_active and not user.is_active):
        qualifier = "an active " if require_active else "a "
        raise InvalidOrganizationInput(f"The {label} must be {qualifier}{role_code}.")
    return user


def _lock_active_user(user_id: UUID, role_code: str, label: str) -> User:
    return _lock_user_with_role(user_id, role_code, label, require_active=True)


def _lock_active_college(college_id: UUID) -> College:
    college = (
        College.objects.select_for_update()
        .select_related("campus")
        .filter(pk=college_id)
        .first()
    )
    if college is None:
        raise OrganizationNotFound("The requested college was not found.")
    if not college.is_active or not college.campus.is_active:
        raise OrganizationConflict("The College and its Campus must both be active.")
    return college


def set_student_affiliation(*, student_id: UUID, college_id: UUID, context: AuditContext) -> StudentAffiliation:
    with transaction.atomic():
        student = _lock_active_user(student_id, "STUDENT", "student")
        college = _lock_active_college(college_id)
        current = StudentAffiliation.objects.select_for_update().filter(student_id=student.pk).first()
        if current is not None and current.college_id == college.pk:
            return current
        previous = str(current.college_id) if current is not None else None
        if current is None:
            current = StudentAffiliation.objects.create(
                student=student,
                college=college,
                assigned_by=_actor(context),
            )
            action = ORGANIZATION_STUDENT_AFFILIATION_ASSIGNED
        else:
            current.college = college
            current.assigned_by = _actor(context)
            current.save(update_fields=["college", "assigned_by", "updated_at"])
            action = ORGANIZATION_STUDENT_AFFILIATION_CHANGED
        record_event(
            context=context,
            action=action,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.studentaffiliation",
            target_id=student.pk,
            metadata={"previous_college_id": previous, "new_college_id": str(college.pk)},
        )
        return current


def remove_student_affiliation(*, student_id: UUID, context: AuditContext) -> bool:
    with transaction.atomic():
        _lock_user_with_role(student_id, "STUDENT", "student", require_active=False)
        current = StudentAffiliation.objects.select_for_update().filter(student_id=student_id).first()
        if current is None:
            return False
        college_id = str(current.college_id)
        current.delete()
        record_event(
            context=context,
            action=ORGANIZATION_STUDENT_AFFILIATION_REMOVED,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.studentaffiliation",
            target_id=student_id,
            metadata={"college_id": college_id},
        )
        return True


def set_counselor_responsibility(*, college_id: UUID, counselor_id: UUID, context: AuditContext) -> CounselorResponsibility:
    with transaction.atomic():
        college = _lock_active_college(college_id)
        counselor = _lock_active_user(counselor_id, "COUNSELOR", "counselor")
        current = (
            CounselorResponsibility.objects.select_for_update()
            .filter(college_id=college.pk)
            .first()
        )
        if current is not None and current.counselor_id == counselor.pk:
            return current
        previous = str(current.counselor_id) if current is not None else None
        if current is None:
            current = CounselorResponsibility.objects.create(
                college=college,
                counselor=counselor,
                assigned_by=_actor(context),
            )
            action = ORGANIZATION_COUNSELOR_RESPONSIBILITY_ASSIGNED
        else:
            current.counselor = counselor
            current.assigned_by = _actor(context)
            current.save(update_fields=["counselor", "assigned_by", "updated_at"])
            action = ORGANIZATION_COUNSELOR_RESPONSIBILITY_CHANGED
        record_event(
            context=context,
            action=action,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.counselorresponsibility",
            target_id=college.pk,
            metadata={
                "previous_counselor_id": previous,
                "new_counselor_id": str(counselor.pk),
            },
        )
        return current


def remove_counselor_responsibility(*, college_id: UUID, context: AuditContext) -> bool:
    with transaction.atomic():
        _lock_active_college(college_id)
        current = (
            CounselorResponsibility.objects.select_for_update()
            .filter(college_id=college_id)
            .first()
        )
        if current is None:
            return False
        counselor_id = str(current.counselor_id)
        current.delete()
        record_event(
            context=context,
            action=ORGANIZATION_COUNSELOR_RESPONSIBILITY_REMOVED,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.counselorresponsibility",
            target_id=college_id,
            metadata={"counselor_id": counselor_id},
        )
        return True


def set_staff_supervisor(*, staff_id: UUID, supervisor_id: UUID, context: AuditContext) -> StaffSupervision:
    with transaction.atomic():
        staff = _lock_active_user(staff_id, "GUIDANCE_SERVICES_STAFF", "staff member")
        supervisor = _lock_active_user(supervisor_id, "COUNSELOR", "supervisor")
        current = StaffSupervision.objects.select_for_update().filter(staff_id=staff.pk).first()
        if current is not None and current.supervisor_id == supervisor.pk:
            return current
        previous = str(current.supervisor_id) if current is not None else None
        if current is None:
            current = StaffSupervision.objects.create(
                staff=staff,
                supervisor=supervisor,
                assigned_by=_actor(context),
            )
            action = ORGANIZATION_STAFF_SUPERVISION_ASSIGNED
        else:
            current.supervisor = supervisor
            current.assigned_by = _actor(context)
            current.save(update_fields=["supervisor", "assigned_by", "updated_at"])
            action = ORGANIZATION_STAFF_SUPERVISION_CHANGED
        record_event(
            context=context,
            action=action,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.staffsupervision",
            target_id=staff.pk,
            metadata={
                "previous_supervisor_id": previous,
                "new_supervisor_id": str(supervisor.pk),
            },
        )
        return current


def remove_staff_supervisor(*, staff_id: UUID, context: AuditContext) -> bool:
    with transaction.atomic():
        _lock_user_with_role(
            staff_id,
            "GUIDANCE_SERVICES_STAFF",
            "staff member",
            require_active=False,
        )
        current = StaffSupervision.objects.select_for_update().filter(staff_id=staff_id).first()
        if current is None:
            return False
        supervisor_id = str(current.supervisor_id)
        current.delete()
        record_event(
            context=context,
            action=ORGANIZATION_STAFF_SUPERVISION_REMOVED,
            outcome=AuditOutcome.SUCCESS,
            target_type="organization.staffsupervision",
            target_id=staff_id,
            metadata={"supervisor_id": supervisor_id},
        )
        return True


def list_people(*, role: str, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE, search: str | None = None) -> PeoplePage:
    allowed = {"COUNSELOR", "GUIDANCE_SERVICES_STAFF", "STUDENT"}
    if role not in allowed:
        raise InvalidOrganizationInput(
            "role must be COUNSELOR, GUIDANCE_SERVICES_STAFF, or STUDENT"
        )
    if type(page) is not int or page < 1:
        raise InvalidOrganizationInput("page must be a positive integer")
    if type(page_size) is not int or not 1 <= page_size <= MAX_PAGE_SIZE:
        raise InvalidOrganizationInput(f"page_size must be between 1 and {MAX_PAGE_SIZE}")
    qs = (
        User.objects.filter(role__code=role)
        .select_related("role")
        .order_by("last_name", "first_name", "id")
    )
    if search and search.strip():
        term = search.strip()[:254]
        qs = qs.filter(
            Q(email__icontains=term)
            | Q(first_name__icontains=term)
            | Q(last_name__icontains=term)
        )
    offset = (page - 1) * page_size
    rows = list(qs[offset : offset + page_size + 1])
    return PeoplePage(tuple(rows[:page_size]), page, page_size, len(rows) > page_size)
