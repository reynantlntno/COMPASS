"""Celery task boundary with request-correlation propagation."""

from __future__ import annotations

import logging

from celery import Task, shared_task

from compass.common.correlation import (
    get_current_request_id,
    normalize_request_id,
    reset_current_request_id,
    set_current_request_id,
)

logger = logging.getLogger("compass.tasks")


class CorrelationTask(Task):
    """Carry a trusted request ID in task headers without logging sensitive arguments."""

    abstract = True

    def apply_async(self, args=None, kwargs=None, *, request_id=None, **options):
        correlation_id = normalize_request_id(request_id) or get_current_request_id()
        if correlation_id:
            headers = dict(options.get("headers") or {})
            headers.setdefault("request_id", correlation_id)
            options["headers"] = headers
        return super().apply_async(args=args, kwargs=kwargs, **options)

    def __call__(self, *args, **kwargs):
        headers = getattr(self.request, "headers", None) or {}
        correlation_id = normalize_request_id(headers.get("request_id"))
        token = set_current_request_id(correlation_id)
        try:
            return super().__call__(*args, **kwargs)
        finally:
            reset_current_request_id(token)


@shared_task(bind=True, base=CorrelationTask, name="compass.infrastructure.noop")
def infrastructure_noop(self):
    """Harmless smoke-test task for validating worker and broker wiring."""
    request_id = get_current_request_id()
    logger.info(
        "infrastructure diagnostic task completed",
        extra={
            "event": "diagnostic_task_completed",
            "request_id": request_id,
            "task_name": self.name,
            "task_id": self.request.id,
        },
    )
    return {"status": "ok", "request_id": request_id}
