"""Structured JSON logs with safe request/task context."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from compass.common.correlation import get_current_request_id


class JsonFormatter(logging.Formatter):
    """Emit controlled fields and never serialize request bodies or query strings."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": getattr(record, "event", record.getMessage()),
        }
        request_id = getattr(record, "request_id", None) or get_current_request_id()
        if request_id:
            payload["request_id"] = request_id

        for field in (
            "method",
            "path",
            "status_code",
            "duration_ms",
            "task_name",
            "task_id",
        ):
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value

        if record.exc_info:
            payload["exception_type"] = record.exc_info[0].__name__

        return json.dumps(payload, separators=(",", ":"), default=str)
