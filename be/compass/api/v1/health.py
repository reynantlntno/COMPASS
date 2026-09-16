"""Liveness and dependency-backed readiness endpoints."""

from __future__ import annotations

import logging

from django.db import connection
from ninja import Router, Schema, Status

logger = logging.getLogger("compass.health")
router = Router(tags=["health"])


class HealthResponse(Schema):
    status: str
    checks: dict[str, str]


@router.get(
    "/live",
    response=HealthResponse,
    operation_id="healthLive",
    summary="Process liveness",
)
def live(request):
    return {"status": "ok", "checks": {"application": "ok"}}


@router.get(
    "/ready",
    response={200: HealthResponse, 503: HealthResponse},
    operation_id="healthReady",
    summary="Dependency-backed readiness",
)
def ready(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    except Exception:
        logger.warning("database readiness check failed", extra={"event": "readiness_failed"})
        return Status(
            503,
            {"status": "not_ready", "checks": {"application": "ok", "database": "failed"}},
        )
    return Status(
        200,
        {"status": "ok", "checks": {"application": "ok", "database": "ok"}},
    )
