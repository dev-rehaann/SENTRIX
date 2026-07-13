"""Map the one canonical Vestrix alert dictionary to SOC output formats."""

from __future__ import annotations

import argparse
import json
import math
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, NotRequired, TypedDict

SOC_SCHEMA_VERSION = "1.0"
OCSF_VERSION = "1.8.0"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$")
_CLASSES = frozenset({"intrusion", "normal", "sensor_tamper"})
_CONFIDENCE_LEVELS = frozenset({"low", "borderline", "high"})
_PACS_STATUSES = frozenset({"matched", "missing", "unknown", "not_applicable"})


class AlertValidationError(ValueError):
    """Raised when a dictionary does not conform to SCHEMA.md."""


class ShapContribution(TypedDict):
    """Narrow SOC representation of one SHAP contribution."""

    feature: str
    value: float
    rank: NotRequired[int]


CanonicalAlert = TypedDict(
    "CanonicalAlert",
    {
        "schema_version": Literal["1.0"],
        "source": Literal["vestrix"],
        "event_id": str,
        "ts_utc": str,
        "node_id": str,
        "site_id": str,
        "zone_id": str,
        "class": Literal["intrusion", "normal", "sensor_tamper"],
        "confidence": float,
        "confidence_level": Literal["low", "borderline", "high"],
        "model_id": str,
        "top_shap": list[ShapContribution],
        "pacs_event_status": Literal["matched", "missing", "unknown", "not_applicable"],
        "pacs_reader_id": str | None,
        "pacs_event_id": str | None,
        "csi_window_sha256": NotRequired[str],
        "sequence_number": NotRequired[int],
        "seq": NotRequired[int],
        "record_hash": NotRequired[str],
    },
)


_REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "source",
        "event_id",
        "ts_utc",
        "node_id",
        "site_id",
        "zone_id",
        "class",
        "confidence",
        "confidence_level",
        "model_id",
        "top_shap",
        "pacs_event_status",
        "pacs_reader_id",
        "pacs_event_id",
    }
)
_OPTIONAL_FIELDS = frozenset(
    {"csi_window_sha256", "sequence_number", "seq", "record_hash"}
)


def confidence_level(confidence: float) -> str:
    """Return the contract-defined confidence band."""
    if confidence >= 0.90:
        return "high"
    if confidence >= 0.60:
        return "borderline"
    return "low"


def validate_alert(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and copy a canonical alert without mutating the caller."""
    if not isinstance(alert, Mapping) or not all(isinstance(key, str) for key in alert):
        raise AlertValidationError("alert must be an object with string keys")

    keys = set(alert)
    missing = _REQUIRED_FIELDS - keys
    unknown = keys - _REQUIRED_FIELDS - _OPTIONAL_FIELDS
    if missing:
        raise AlertValidationError(f"missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise AlertValidationError(f"unknown fields: {', '.join(sorted(unknown))}")

    if alert["schema_version"] != SOC_SCHEMA_VERSION:
        raise AlertValidationError("schema_version must be '1.0'")
    if alert["source"] != "vestrix":
        raise AlertValidationError("source must be 'vestrix'")
    for field in ("event_id", "node_id", "site_id", "zone_id", "model_id"):
        _require_nonempty_string(alert[field], field)

    timestamp = alert["ts_utc"]
    if not isinstance(timestamp, str) or not _TIMESTAMP_RE.fullmatch(timestamp):
        raise AlertValidationError("ts_utc must be an RFC 3339 UTC string ending in Z")
    _to_epoch_millis(timestamp)

    event_class = alert["class"]
    if event_class not in _CLASSES:
        raise AlertValidationError("class must be intrusion, normal, or sensor_tamper")

    confidence = alert["confidence"]
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not math.isfinite(confidence)
        or not 0 <= confidence <= 1
    ):
        raise AlertValidationError("confidence must be finite and in [0,1]")
    confidence = float(confidence)
    level = alert["confidence_level"]
    if level not in _CONFIDENCE_LEVELS:
        raise AlertValidationError("invalid confidence_level")
    expected_level = confidence_level(confidence)
    if level != expected_level:
        raise AlertValidationError(
            f"confidence_level must be {expected_level!r} for confidence {confidence}"
        )

    _validate_top_shap(alert["top_shap"])
    _validate_pacs(alert)

    for field in ("csi_window_sha256", "record_hash"):
        if field in alert:
            value = alert[field]
            if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
                raise AlertValidationError(
                    f"{field} must be 64 lowercase hexadecimal characters"
                )
    for field in ("sequence_number", "seq"):
        if field in alert:
            _require_nonnegative_integer(alert[field], field)

    return deepcopy(dict(alert))


def to_wazuh(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Return the flat JSON shape consumed by the Vestrix Wazuh decoder."""
    canonical = validate_alert(alert)
    top_shap = canonical.pop("top_shap")
    output = {key: value for key, value in canonical.items() if value is not None}
    if top_shap:
        output["shap_top_feature"] = top_shap[0]["feature"]
        output["shap_top_value"] = top_shap[0]["value"]
    else:
        output["shap_top_feature"] = "none"
        output["shap_top_value"] = 0.0
    return output


def to_ocsf(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Map a canonical alert to an OCSF 1.8.0 Detection Finding event."""
    canonical = validate_alert(alert)
    event_class = canonical["class"]
    confidence = float(canonical["confidence"])
    confidence_id = {"low": 1, "borderline": 2, "high": 3}[
        canonical["confidence_level"]
    ]
    time = _to_epoch_millis(canonical["ts_utc"])
    severity_id, severity = _severity(canonical)
    title = _title(canonical)

    event: dict[str, Any] = {
        "activity_id": 1,
        "activity_name": "Create",
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "type_uid": 200401,
        "type_name": "Detection Finding: Create",
        "time": time,
        "severity_id": severity_id,
        "severity": severity,
        "confidence_id": confidence_id,
        "confidence": {1: "Low", 2: "Medium", 3: "High"}[confidence_id],
        "confidence_score": round(confidence * 100),
        "status_id": 1,
        "status": "New",
        "is_alert": event_class != "normal",
        "message": title,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "Vestrix",
                "vendor_name": "Vestrix",
                "version": SOC_SCHEMA_VERSION,
            },
            "original_event_uid": canonical["event_id"],
            "original_time": canonical["ts_utc"],
            "log_name": "vestrix-alerts",
            "log_provider": "Vestrix",
            "source": "Vestrix canonical SOC alert",
        },
        "finding_info": {
            "uid": canonical["event_id"],
            "title": title,
            "desc": (
                f"Vestrix classified physical activity as {event_class} in "
                f"{canonical['site_id']}/{canonical['zone_id']}."
            ),
            "analytic": {
                "name": canonical["model_id"],
                "uid": canonical["model_id"],
                "type_id": 4,
                "type": "Learning (ML/DL)",
            },
            "types": ["Physical Security", "WiFi CSI Sensing"],
        },
        "device": {
            "uid": canonical["node_id"],
            "name": canonical["node_id"],
            "type_id": 99,
            "type": "WiFi CSI sensor",
            "vendor_name": "Vestrix",
        },
        "unmapped": {"vestrix": canonical},
    }
    return event


def _severity(alert: Mapping[str, Any]) -> tuple[int, str]:
    event_class = alert["class"]
    if event_class == "normal":
        return 1, "Informational"
    if event_class == "sensor_tamper":
        return 4, "High"
    if alert["pacs_event_status"] == "missing":
        return 5, "Critical"
    return {
        "high": (4, "High"),
        "borderline": (3, "Medium"),
        "low": (2, "Low"),
    }[alert["confidence_level"]]


def _title(alert: Mapping[str, Any]) -> str:
    event_class = alert["class"]
    zone = f"{alert['site_id']}/{alert['zone_id']}"
    if event_class == "sensor_tamper":
        return f"Vestrix sensor tamper detected at {zone}"
    if event_class == "normal":
        return f"Vestrix benign physical activity at {zone}"
    if alert["pacs_event_status"] == "missing":
        return f"Vestrix intrusion without corresponding PACS event at {zone}"
    return f"Vestrix physical intrusion detected at {zone}"


def _to_epoch_millis(value: str) -> int:
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise AlertValidationError("ts_utc is not a valid calendar timestamp") from exc
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise AlertValidationError("ts_utc must represent UTC")
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = parsed - epoch
    return delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000


def _validate_top_shap(value: object) -> None:
    if not isinstance(value, list):
        raise AlertValidationError("top_shap must be an array")
    for index, item in enumerate(value):
        if not isinstance(item, dict) or not all(isinstance(key, str) for key in item):
            raise AlertValidationError(f"top_shap[{index}] must be an object")
        unknown = set(item) - {"feature", "value", "rank"}
        if unknown or not {"feature", "value"}.issubset(item):
            raise AlertValidationError(
                f"top_shap[{index}] must contain feature/value and optional rank"
            )
        _require_nonempty_string(item["feature"], f"top_shap[{index}].feature")
        contribution = item["value"]
        if (
            isinstance(contribution, bool)
            or not isinstance(contribution, (int, float))
            or not math.isfinite(contribution)
        ):
            raise AlertValidationError(f"top_shap[{index}].value must be finite")
        if "rank" in item:
            rank = item["rank"]
            if isinstance(rank, bool) or not isinstance(rank, int) or rank <= 0:
                raise AlertValidationError(
                    f"top_shap[{index}].rank must be a positive integer"
                )


def _validate_pacs(alert: Mapping[str, Any]) -> None:
    status = alert["pacs_event_status"]
    if status not in _PACS_STATUSES:
        raise AlertValidationError("invalid pacs_event_status")
    reader_id = alert["pacs_reader_id"]
    event_id = alert["pacs_event_id"]
    _require_optional_string(reader_id, "pacs_reader_id")
    _require_optional_string(event_id, "pacs_event_id")
    if status == "matched" and (reader_id is None or event_id is None):
        raise AlertValidationError("matched PACS status requires both PACS IDs")
    if status == "missing" and event_id is not None:
        raise AlertValidationError("missing PACS status requires null pacs_event_id")
    if status == "not_applicable" and (reader_id is not None or event_id is not None):
        raise AlertValidationError("not_applicable PACS status requires null PACS IDs")


def _require_nonempty_string(value: object, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise AlertValidationError(f"{field} must be a non-empty string")


def _require_optional_string(value: object, field: str) -> None:
    if value is not None:
        _require_nonempty_string(value, field)


def _require_nonnegative_integer(value: object, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AlertValidationError(f"{field} must be a non-negative integer")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("format", choices=("wazuh", "ocsf"))
    parser.add_argument("alert", type=Path, help="canonical alert JSON path")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    """Map one canonical JSON file and print compact JSON to stdout."""
    args = _parse_args(argv)
    source = json.loads(args.alert.read_text(encoding="utf-8"))
    mapper = to_wazuh if args.format == "wazuh" else to_ocsf
    print(json.dumps(mapper(source), separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
