"""Structured JSON logging helpers."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any


class JSONFormatter(logging.Formatter):
    """Format collector records as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        output: dict[str, Any] = {
            "timestamp_utc": datetime.fromtimestamp(record.created, UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "event": getattr(record, "event", "collector_log"),
            "message": record.getMessage(),
        }
        decision_fields = getattr(record, "decision_fields", None)
        if isinstance(decision_fields, dict):
            output.update(decision_fields)
        return json.dumps(output, separators=(",", ":"), sort_keys=True)


def configure_logging(level: int = logging.INFO) -> None:
    """Configure process logging for CLI execution."""
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
