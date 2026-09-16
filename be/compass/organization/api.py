"""Thin Django Ninja API for Organization structure and default responsibility configuration."""

from __future__ import annotations

from enum import Enum
from typing import NoReturn
from uuid import UUID

from ninja import Router, Schema, Status
from pydantic import ConfigDict

from compass.audit.context import AuditContext
from compass.authentication.api import session_auth
from compass.authentication.sessions import RecentMFARequired, require_recent_mfa
from compass.common.api import response_with_errors
from compass.common.errors import APIError
from compass.organization.models import CounselorResponsibility, StaffSupervision, StudentAffiliation
from compass.organization.services import (
    DEFAULT_PAGE_SIZE,
    InvalidOrganizationInput,
    OrganizationConflict,
    OrganizationError,
    OrganizationNotFound,
    create_campus,
    create_college,
    get_campus,
    get_college,
    list_campuses,
    list_colleges,
    list_people,
    remove_counselor_responsibility,
    remove_staff_supervisor,
    remove_student_affiliation,
    set_campus_active,
    set_college_active,
    set_counselor_responsibility,
    set_staff_supervisor,
    set_student_affiliation,
    update_campus,
    update_college,
)

router = Router(tags=["organization"])


class StrictSchema(Schema):
    model_config = ConfigDict(extra="forbid")


class CampusSummary(StrictSchema):
    id: UUID
    code: str
    name: str
    is_active: bool


class CampusListResponse(StrictSchema):
    items: list[CampusSummary]


class CampusCreateRequest(StrictSchema):
    code: str
    name: str


class CampusUpdateRequest(StrictSchema):
    code: str | None = None
    name: str | None = None


class CollegeSummary(StrictSchema):
    id: UUID
    code: str
    name: str
    campus: CampusSummary
    is_active: bool


class CollegeListResponse(StrictSchema):
    items: list[CollegeSummary]


class CollegeCreateRequest(StrictSchema):
    campus_id: UUID
    code: str
    name: str


class CollegeUpdateRequest(StrictSchema):
    code: str | None = None
    name: str | None = None


class PersonSummary(StrictSchema):
    id: UUID
    full_name: str
    email: str
    role: str
    is_active: bool


class PersonListResponse(StrictSchema):
    items: list[PersonSummary]
    page: int
    page_size: int
    has_next: bool


class CounselorAssignmentRequest(StrictSchema):
    counselor_id: UUID


class StaffSupervisorRequest(StrictSchema):
    supervisor_id: UUID


class StudentAffiliationRequest(StrictSchema):
    college_id: UUID


class CounselorResponsibilityResponse(StrictSchema):
    college: CollegeSummary
    counselor: PersonSummary


class CounselorResponsibilityListResponse(StrictSchema):
    items: list[CounselorResponsibilityResponse]


class StaffSupervisionResponse(StrictSchema):
    staff: PersonSummary
    supervisor: PersonSummary


class StaffSupervisionListResponse(StrictSchema):
    items: list[StaffSupervisionResponse]


class StudentAffiliationResponse(StrictSchema):
    student: PersonSummary
    college: CollegeSummary


class StudentAffiliationListResponse(StrictSchema):
    items: list[StudentAffiliationResponse]


class RemovedResponse(StrictSchema):
    removed: bool


class OrganizationRole(str, Enum):
    COUNSELOR = "COUNSELOR"
    GUIDANCE_SERVICES_STAFF = "GUIDANCE_SERVICES_STAFF"
    STUDENT = "STUDENT"


def _context(request) -> AuditContext:
    return AuditContext.from_request(request, actor=request.auth_user)


def _require(request, capability: str, *, recent_mfa: bool = False) -> None:
    if not request.auth_user.has_capability(capability):
        raise APIError(403, "permission_denied", f"The {capability} capability is required.")
    if recent_mfa:
        try:
            require_recent_mfa(request.auth_session)
        except RecentMFARequired as exc:
            raise APIError(403, "recent_mfa_required", "Recent MFA is required.") from exc


def _raise(exc: OrganizationError) -> NoReturn:
    if isinstance(exc, OrganizationNotFound):
        raise APIError(404, "organization_not_found", str(exc)) from exc
    if isinstance(exc, OrganizationConflict):
        raise APIError(409, "organization_conflict", str(exc)) from exc
    if isinstance(exc, InvalidOrganizationInput):
        raise APIError(422, "invalid_organization_request", str(exc)) from exc
    raise APIError(500, "internal_error", "The organization operation could not be completed.") from exc


def _campus(campus) -> dict[str, object]:
    return {"id": campus.pk, "code": campus.code, "name": campus.name, "is_active": campus.is_active}


def _college(college) -> dict[str, object]:
    return {
        "id": college.pk,
        "code": college.code,
        "name": college.name,
        "campus": _campus(college.campus),
        "is_active": college.is_active,
    }


def _person(user) -> dict[str, object]:
    return {
        "id": user.pk,
        "full_name": user.get_full_name(),
        "email": user.email,
        "role": user.role.code,
        "is_active": user.is_active,
    }


@router.get(
    "/campuses",
    response=response_with_errors(CampusListResponse, 401, 403),
    auth=session_auth,
    operation_id="organizationListCampuses",
)
def campuses(request, is_active: bool | None = None, search: str | None = None):
    _require(request, "organization.view")
    return {"items": [_campus(item) for item in list_campuses(is_active=is_active, search=search)]}


@router.post(
    "/campuses",
    response=response_with_errors(CampusSummary, 401, 403, 409, 422, success_status=201),
    auth=session_auth,
    operation_id="organizationCreateCampus",
)
def campus_create(request, payload: CampusCreateRequest):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        campus = create_campus(code=payload.code, name=payload.name, context=_context(request))
    except OrganizationError as exc:
        _raise(exc)
    return Status(201, _campus(campus))


@router.get(
    "/campuses/{campus_id}",
    response=response_with_errors(CampusSummary, 401, 403, 404, 422),
    auth=session_auth,
    operation_id="organizationGetCampus",
)
def campus_get(request, campus_id: UUID):
    _require(request, "organization.view")
    try:
        return _campus(get_campus(campus_id))
    except OrganizationError as exc:
        _raise(exc)


@router.patch(
    "/campuses/{campus_id}",
    response=response_with_errors(CampusSummary, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationUpdateCampus",
)
def campus_update(request, campus_id: UUID, payload: CampusUpdateRequest):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        return _campus(
            update_campus(
                campus_id=campus_id,
                changes=payload.model_dump(exclude_unset=True),
                context=_context(request),
            )
        )
    except OrganizationError as exc:
        _raise(exc)


@router.post(
    "/campuses/{campus_id}/enable",
    response=response_with_errors(CampusSummary, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationEnableCampus",
)
def campus_enable(request, campus_id: UUID):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        return _campus(set_campus_active(campus_id=campus_id, is_active=True, context=_context(request)))
    except OrganizationError as exc:
        _raise(exc)


@router.post(
    "/campuses/{campus_id}/disable",
    response=response_with_errors(CampusSummary, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationDisableCampus",
)
def campus_disable(request, campus_id: UUID):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        return _campus(set_campus_active(campus_id=campus_id, is_active=False, context=_context(request)))
    except OrganizationError as exc:
        _raise(exc)


@router.get(
    "/colleges",
    response=response_with_errors(CollegeListResponse, 401, 403, 422),
    auth=session_auth,
    operation_id="organizationListColleges",
)
def colleges(request, campus_id: UUID | None = None, is_active: bool | None = None, search: str | None = None):
    _require(request, "organization.view")
    return {
        "items": [
            _college(item)
            for item in list_colleges(campus_id=campus_id, is_active=is_active, search=search)
        ]
    }


@router.post(
    "/colleges",
    response=response_with_errors(CollegeSummary, 401, 403, 404, 409, 422, success_status=201),
    auth=session_auth,
    operation_id="organizationCreateCollege",
)
def college_create(request, payload: CollegeCreateRequest):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        college = create_college(
            campus_id=payload.campus_id,
            code=payload.code,
            name=payload.name,
            context=_context(request),
        )
    except OrganizationError as exc:
        _raise(exc)
    return Status(201, _college(college))


@router.get(
    "/colleges/{college_id}",
    response=response_with_errors(CollegeSummary, 401, 403, 404, 422),
    auth=session_auth,
    operation_id="organizationGetCollege",
)
def college_get(request, college_id: UUID):
    _require(request, "organization.view")
    try:
        return _college(get_college(college_id))
    except OrganizationError as exc:
        _raise(exc)


@router.patch(
    "/colleges/{college_id}",
    response=response_with_errors(CollegeSummary, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationUpdateCollege",
)
def college_update(request, college_id: UUID, payload: CollegeUpdateRequest):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        return _college(
            update_college(
                college_id=college_id,
                changes=payload.model_dump(exclude_unset=True),
                context=_context(request),
            )
        )
    except OrganizationError as exc:
        _raise(exc)


@router.post(
    "/colleges/{college_id}/enable",
    response=response_with_errors(CollegeSummary, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationEnableCollege",
)
def college_enable(request, college_id: UUID):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        return _college(set_college_active(college_id=college_id, is_active=True, context=_context(request)))
    except OrganizationError as exc:
        _raise(exc)


@router.post(
    "/colleges/{college_id}/disable",
    response=response_with_errors(CollegeSummary, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationDisableCollege",
)
def college_disable(request, college_id: UUID):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        return _college(set_college_active(college_id=college_id, is_active=False, context=_context(request)))
    except OrganizationError as exc:
        _raise(exc)


@router.get(
    "/counselor-responsibilities",
    response=response_with_errors(CounselorResponsibilityListResponse, 401, 403),
    auth=session_auth,
    operation_id="organizationListCounselorResponsibilities",
)
def counselor_responsibilities(
    request,
    counselor_id: UUID | None = None,
    college_id: UUID | None = None,
    campus_id: UUID | None = None,
):
    _require(request, "organization.manage")
    qs = CounselorResponsibility.objects.select_related(
        "college__campus", "counselor__role"
    ).order_by("college__campus__code", "college__code")
    if counselor_id is not None:
        qs = qs.filter(counselor_id=counselor_id)
    if college_id is not None:
        qs = qs.filter(college_id=college_id)
    if campus_id is not None:
        qs = qs.filter(college__campus_id=campus_id)
    return {
        "items": [
            {"college": _college(item.college), "counselor": _person(item.counselor)}
            for item in qs
        ]
    }


@router.put(
    "/colleges/{college_id}/counselor",
    response=response_with_errors(CounselorResponsibilityResponse, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationSetCollegeCounselor",
)
def college_counselor_set(request, college_id: UUID, payload: CounselorAssignmentRequest):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        item = set_counselor_responsibility(
            college_id=college_id,
            counselor_id=payload.counselor_id,
            context=_context(request),
        )
    except OrganizationError as exc:
        _raise(exc)
    return {"college": _college(item.college), "counselor": _person(item.counselor)}


@router.delete(
    "/colleges/{college_id}/counselor",
    response=response_with_errors(RemovedResponse, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationRemoveCollegeCounselor",
)
def college_counselor_remove(request, college_id: UUID):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        removed = remove_counselor_responsibility(college_id=college_id, context=_context(request))
    except OrganizationError as exc:
        _raise(exc)
    return {"removed": removed}


@router.get(
    "/staff-supervisions",
    response=response_with_errors(StaffSupervisionListResponse, 401, 403),
    auth=session_auth,
    operation_id="organizationListStaffSupervisions",
)
def staff_supervisions(request):
    _require(request, "organization.manage")
    qs = StaffSupervision.objects.select_related(
        "staff__role", "supervisor__role"
    ).order_by("staff__last_name", "staff__id")
    return {
        "items": [
            {"staff": _person(item.staff), "supervisor": _person(item.supervisor)}
            for item in qs
        ]
    }


@router.put(
    "/staff/{staff_id}/supervisor",
    response=response_with_errors(StaffSupervisionResponse, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationSetStaffSupervisor",
)
def staff_supervisor_set(request, staff_id: UUID, payload: StaffSupervisorRequest):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        item = set_staff_supervisor(
            staff_id=staff_id,
            supervisor_id=payload.supervisor_id,
            context=_context(request),
        )
    except OrganizationError as exc:
        _raise(exc)
    return {"staff": _person(item.staff), "supervisor": _person(item.supervisor)}


@router.delete(
    "/staff/{staff_id}/supervisor",
    response=response_with_errors(RemovedResponse, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationRemoveStaffSupervisor",
)
def staff_supervisor_remove(request, staff_id: UUID):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        removed = remove_staff_supervisor(staff_id=staff_id, context=_context(request))
    except OrganizationError as exc:
        _raise(exc)
    return {"removed": removed}


@router.get(
    "/student-affiliations",
    response=response_with_errors(StudentAffiliationListResponse, 401, 403),
    auth=session_auth,
    operation_id="organizationListStudentAffiliations",
)
def student_affiliations(request):
    _require(request, "organization.manage")
    qs = StudentAffiliation.objects.select_related(
        "student__role", "college__campus"
    ).order_by("student__last_name", "student__id")
    return {
        "items": [
            {"student": _person(item.student), "college": _college(item.college)}
            for item in qs
        ]
    }


@router.put(
    "/students/{student_id}/affiliation",
    response=response_with_errors(StudentAffiliationResponse, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationSetStudentAffiliation",
)
def student_affiliation_set(request, student_id: UUID, payload: StudentAffiliationRequest):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        item = set_student_affiliation(
            student_id=student_id,
            college_id=payload.college_id,
            context=_context(request),
        )
    except OrganizationError as exc:
        _raise(exc)
    return {"student": _person(item.student), "college": _college(item.college)}


@router.delete(
    "/students/{student_id}/affiliation",
    response=response_with_errors(RemovedResponse, 401, 403, 404, 409, 422),
    auth=session_auth,
    operation_id="organizationRemoveStudentAffiliation",
)
def student_affiliation_remove(request, student_id: UUID):
    _require(request, "organization.manage", recent_mfa=True)
    try:
        removed = remove_student_affiliation(student_id=student_id, context=_context(request))
    except OrganizationError as exc:
        _raise(exc)
    return {"removed": removed}


@router.get(
    "/people",
    response=response_with_errors(PersonListResponse, 401, 403, 422),
    auth=session_auth,
    operation_id="organizationListEligiblePeople",
)
def people(
    request,
    role: OrganizationRole,
    search: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
):
    _require(request, "organization.manage")
    try:
        result = list_people(role=role.value, search=search, page=page, page_size=page_size)
    except OrganizationError as exc:
        _raise(exc)
    return {
        "items": [_person(item) for item in result.items],
        "page": result.page,
        "page_size": result.page_size,
        "has_next": result.has_next,
    }
