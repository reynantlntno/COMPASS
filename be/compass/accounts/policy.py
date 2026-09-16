"""Version-controlled identity policy synchronized into PostgreSQL."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RoleDefinition:
    code: str
    name: str
    description: str


@dataclass(frozen=True, slots=True)
class DesignationDefinition:
    code: str
    name: str
    description: str


@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    code: str
    name: str
    description: str


ROLE_DEFINITIONS = (
    RoleDefinition(
        code="IT_ADMIN",
        name="IT Administrator",
        description="Technical administrator for COMPASS account and platform operations.",
    ),
    RoleDefinition(
        code="COUNSELOR",
        name="Counselor",
        description="Operational counseling role.",
    ),
    RoleDefinition(
        code="GUIDANCE_SERVICES_STAFF",
        name="Guidance Services Staff",
        description="Operational guidance services staff role.",
    ),
    RoleDefinition(
        code="STUDENT",
        name="Student",
        description="Student account role.",
    ),
)

DESIGNATION_DEFINITIONS = (
    DesignationDefinition(
        code="HEAD_GUIDANCE_COUNSELOR",
        name="Head Guidance Counselor",
        description="Institutional designation for the head guidance counselor appointment.",
    ),
    DesignationDefinition(
        code="DPO",
        name="Data Protection Officer",
        description="Institutional designation for the data protection officer appointment.",
    ),
)

CAPABILITY_DEFINITIONS = (
    CapabilityDefinition(
        code="accounts.view",
        name="View account identity",
        description="View account identity fields through an authorized COMPASS workflow.",
    ),
    CapabilityDefinition(
        code="accounts.manage",
        name="Manage accounts",
        description="Manage account identity and account status through an authorized workflow.",
    ),
    CapabilityDefinition(
        code="organization.view",
        name="View organization",
        description="View safe organizational structure through an authorized COMPASS workflow.",
    ),
    CapabilityDefinition(
        code="organization.manage",
        name="Manage organization",
        description="Manage organizational routing and responsibility configuration.",
    ),
)

# Account identity is visible to operational actors through future, scoped workflows. Account
# management remains an IT_ADMIN responsibility. Scope and sensitive profile data are separate
# concerns and are intentionally not implied by these grants.
ROLE_CAPABILITY_GRANTS: dict[str, frozenset[str]] = {
    "IT_ADMIN": frozenset(
        {"accounts.view", "accounts.manage", "organization.view", "organization.manage"}
    ),
    "COUNSELOR": frozenset({"accounts.view", "organization.view"}),
    "GUIDANCE_SERVICES_STAFF": frozenset({"accounts.view", "organization.view"}),
    "STUDENT": frozenset({"accounts.view", "organization.view"}),
}

# No designation currently adds account-foundation authority. The relationship is still modeled
# explicitly so later domain policy can grant designation-specific capabilities without turning a
# designation into a role.
DESIGNATION_CAPABILITY_GRANTS: dict[str, frozenset[str]] = {
    "HEAD_GUIDANCE_COUNSELOR": frozenset({"organization.manage"}),
    "DPO": frozenset(),
}

ROLE_CODES = frozenset(definition.code for definition in ROLE_DEFINITIONS)
DESIGNATION_CODES = frozenset(definition.code for definition in DESIGNATION_DEFINITIONS)
CAPABILITY_CODES = frozenset(definition.code for definition in CAPABILITY_DEFINITIONS)


def _validate_policy() -> None:
    if set(ROLE_CAPABILITY_GRANTS) != ROLE_CODES:
        raise RuntimeError("role capability policy must define every canonical role exactly once")
    if set(DESIGNATION_CAPABILITY_GRANTS) != DESIGNATION_CODES:
        raise RuntimeError(
            "designation capability policy must define every canonical designation exactly once"
        )
    for role_code, capability_codes in ROLE_CAPABILITY_GRANTS.items():
        if role_code not in ROLE_CODES or not capability_codes <= CAPABILITY_CODES:
            raise RuntimeError(f"invalid role capability policy for {role_code}")
    for designation_code, capability_codes in DESIGNATION_CAPABILITY_GRANTS.items():
        if designation_code not in DESIGNATION_CODES or not capability_codes <= CAPABILITY_CODES:
            raise RuntimeError(f"invalid designation capability policy for {designation_code}")


_validate_policy()
