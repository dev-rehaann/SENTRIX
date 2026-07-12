from __future__ import annotations

import pytest

from sentrix_collector.models import PayloadValidationError, validate_payload


def test_payload_schema_rejects_unknown_fields() -> None:
    payload: dict[str, object] = {
        "schema_version": "0.1",
        "node_id": "node-01",
        "timestamp_utc": "2026-07-12T17:30:00Z",
        "csi_window_sha256": "a" * 64,
        "sequence_number": 1,
        "classification": "intruder",
    }

    with pytest.raises(PayloadValidationError, match="unknown_fields:classification"):
        validate_payload(payload)
