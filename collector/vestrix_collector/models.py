"""Strict v0.1 CSI ingest schema."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal, TypedDict, cast


class PayloadValidationError(ValueError):
    """Raised when an ingest payload does not match the v0.1 schema."""


class CSIEvent(TypedDict):
    schema_version: Literal["0.1"]
    node_id: str
    timestamp_utc: str
    csi_window_sha256: str
    sequence_number: int


_FIELDS = {
    "schema_version",
    "node_id",
    "timestamp_utc",
    "csi_window_sha256",
    "sequence_number",
}
_NODE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_UTC_TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_SEQUENCE_NUMBER = (1 << 64) - 1


def validate_payload(value: object) -> CSIEvent:
    """Validate and return an exact, JSON-compatible CSI event."""
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise PayloadValidationError("payload_not_object")

    keys = set(value)
    if keys != _FIELDS:
        if missing := _FIELDS - keys:
            raise PayloadValidationError(f"missing_fields:{','.join(sorted(missing))}")
        raise PayloadValidationError(
            f"unknown_fields:{','.join(sorted(keys - _FIELDS))}"
        )

    if value["schema_version"] != "0.1":
        raise PayloadValidationError("unsupported_schema_version")

    node_id = value["node_id"]
    if not isinstance(node_id, str) or not _NODE_ID_PATTERN.fullmatch(node_id):
        raise PayloadValidationError("invalid_node_id")

    timestamp = value["timestamp_utc"]
    if not isinstance(timestamp, str) or not _UTC_TIMESTAMP_PATTERN.fullmatch(
        timestamp
    ):
        raise PayloadValidationError("invalid_timestamp_utc")
    try:
        datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise PayloadValidationError("invalid_timestamp_utc") from exc

    digest = value["csi_window_sha256"]
    if not isinstance(digest, str) or not _SHA256_PATTERN.fullmatch(digest):
        raise PayloadValidationError("invalid_csi_window_sha256")

    sequence_number = value["sequence_number"]
    if (
        isinstance(sequence_number, bool)
        or not isinstance(sequence_number, int)
        or not 0 <= sequence_number <= _MAX_SEQUENCE_NUMBER
    ):
        raise PayloadValidationError("invalid_sequence_number")

    return cast(CSIEvent, dict(value))
