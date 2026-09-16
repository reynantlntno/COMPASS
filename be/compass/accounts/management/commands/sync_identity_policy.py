"""Synchronize the version-controlled identity policy into PostgreSQL."""

from __future__ import annotations

from django.core.management.base import BaseCommand
from django.db import transaction

from compass.accounts.models import (
    Capability,
    Designation,
    DesignationCapability,
    Role,
    RoleCapability,
)
from compass.accounts.policy import (
    CAPABILITY_DEFINITIONS,
    DESIGNATION_CAPABILITY_GRANTS,
    DESIGNATION_DEFINITIONS,
    ROLE_CAPABILITY_GRANTS,
    ROLE_DEFINITIONS,
)
from compass.audit.actions import IDENTITY_POLICY_SYNCED
from compass.audit.context import AuditContext
from compass.audit.models import AuditOutcome
from compass.audit.services import record_event


def _sync_definition(model, definition) -> tuple[object, str]:
    defaults = {
        "name": definition.name,
        "description": definition.description,
    }
    obj, created = model.objects.get_or_create(code=definition.code, defaults=defaults)
    if created:
        return obj, "created"

    changed_fields = [
        field_name for field_name, value in defaults.items() if getattr(obj, field_name) != value
    ]
    if changed_fields:
        for field_name in changed_fields:
            setattr(obj, field_name, defaults[field_name])
        obj.save(update_fields=changed_fields)
        return obj, "updated"
    return obj, "unchanged"


class Command(BaseCommand):
    help = "Synchronize canonical COMPASS identity roles, designations, capabilities, and grants."

    def handle(self, *args, **options):
        counts = {
            "roles_created": 0,
            "roles_updated": 0,
            "designations_created": 0,
            "designations_updated": 0,
            "capabilities_created": 0,
            "capabilities_updated": 0,
            "role_grants_created": 0,
            "designation_grants_created": 0,
        }

        with transaction.atomic():
            roles = {}
            for definition in ROLE_DEFINITIONS:
                role, result = _sync_definition(Role, definition)
                roles[definition.code] = role
                if result == "created":
                    counts["roles_created"] += 1
                elif result == "updated":
                    counts["roles_updated"] += 1

            designations = {}
            for definition in DESIGNATION_DEFINITIONS:
                designation, result = _sync_definition(Designation, definition)
                designations[definition.code] = designation
                if result == "created":
                    counts["designations_created"] += 1
                elif result == "updated":
                    counts["designations_updated"] += 1

            capabilities = {}
            for definition in CAPABILITY_DEFINITIONS:
                capability, result = _sync_definition(Capability, definition)
                capabilities[definition.code] = capability
                if result == "created":
                    counts["capabilities_created"] += 1
                elif result == "updated":
                    counts["capabilities_updated"] += 1

            for role_code, capability_codes in ROLE_CAPABILITY_GRANTS.items():
                for capability_code in capability_codes:
                    _grant, created = RoleCapability.objects.get_or_create(
                        role=roles[role_code],
                        capability=capabilities[capability_code],
                    )
                    if created:
                        counts["role_grants_created"] += 1

            for designation_code, capability_codes in DESIGNATION_CAPABILITY_GRANTS.items():
                for capability_code in capability_codes:
                    _grant, created = DesignationCapability.objects.get_or_create(
                        designation=designations[designation_code],
                        capability=capabilities[capability_code],
                    )
                    if created:
                        counts["designation_grants_created"] += 1

            if any(counts.values()):
                record_event(
                    context=AuditContext.system(),
                    action=IDENTITY_POLICY_SYNCED,
                    outcome=AuditOutcome.SUCCESS,
                    metadata=counts,
                )

        self.stdout.write("Identity policy synchronization complete.")
        self.stdout.write(
            "Definitions: "
            f"roles created={counts['roles_created']} updated={counts['roles_updated']}; "
            f"designations created={counts['designations_created']} "
            f"updated={counts['designations_updated']}; "
            f"capabilities created={counts['capabilities_created']} "
            f"updated={counts['capabilities_updated']}."
        )
        self.stdout.write(
            "Baseline grants: "
            f"role grants created={counts['role_grants_created']}; "
            f"designation grants created={counts['designation_grants_created']}. "
            "Unknown database rows were retained."
        )
