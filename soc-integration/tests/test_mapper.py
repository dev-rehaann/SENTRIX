from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

from ocsf.mapper import AlertValidationError, to_ocsf, to_wazuh, validate_alert

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "wazuh" / "sample_events"
SAMPLE_PATHS = sorted(SAMPLES.glob("*.json"))


def load_sample(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("sample_path", SAMPLE_PATHS, ids=lambda path: path.stem)
def test_samples_are_valid_canonical_alerts(sample_path: Path) -> None:
    source = load_sample(sample_path)

    validated = validate_alert(source)

    assert validated == source
    assert validated is not source


@pytest.mark.parametrize("sample_path", SAMPLE_PATHS, ids=lambda path: path.stem)
def test_ocsf_detection_finding_required_fields_and_types(sample_path: Path) -> None:
    source = load_sample(sample_path)

    event = to_ocsf(source)

    assert event["activity_id"] == 1
    assert event["category_uid"] == 2
    assert event["class_uid"] == 2004
    assert event["type_uid"] == 200401
    assert isinstance(event["time"], int) and event["time"] > 0
    assert isinstance(event["severity_id"], int)
    assert event["severity_id"] in {1, 2, 3, 4, 5}
    assert isinstance(event["confidence_score"], int)
    assert 0 <= event["confidence_score"] <= 100
    assert isinstance(event["is_alert"], bool)

    metadata = event["metadata"]
    assert metadata["version"] == "1.8.0"
    assert metadata["original_event_uid"] == source["event_id"]
    assert metadata["original_time"] == source["ts_utc"]
    assert metadata["product"]["name"] == "Sentrix"
    assert metadata["product"]["vendor_name"] == "Sentrix"

    finding_info = event["finding_info"]
    assert finding_info["uid"] == source["event_id"]
    assert finding_info["analytic"]["uid"] == source["model_id"]
    assert finding_info["analytic"]["type_id"] == 4
    assert event["device"]["uid"] == source["node_id"]
    assert event["unmapped"]["sentrix"] == source


@pytest.mark.parametrize("sample_path", SAMPLE_PATHS, ids=lambda path: path.stem)
def test_wazuh_shape_matches_json_decoder_contract(sample_path: Path) -> None:
    source = load_sample(sample_path)

    event = to_wazuh(source)

    assert event["source"] == "sentrix"
    assert event["class"] == source["class"]
    assert event["confidence"] == source["confidence"]
    assert event["confidence_level"] == source["confidence_level"]
    assert event["pacs_event_status"] == source["pacs_event_status"]
    assert isinstance(event["shap_top_feature"], str)
    assert isinstance(event["shap_top_value"], (int, float))
    assert "top_shap" not in event
    assert all(value is not None for value in event.values())
    assert json.loads(json.dumps(event)) == event


def test_confidence_level_mismatch_is_rejected() -> None:
    source = load_sample(SAMPLES / "high_confidence_intrusion.json")
    source["confidence_level"] = "borderline"

    with pytest.raises(AlertValidationError, match="confidence_level must be 'high'"):
        to_ocsf(source)


def test_wazuh_decoder_uses_json_plugin_and_expected_dynamic_fields() -> None:
    decoder_text = (ROOT / "wazuh" / "decoders" / "local_decoder.xml").read_text(
        encoding="utf-8"
    )
    decoder_root = ET.fromstring(f"<root>{decoder_text}</root>")
    decoder = decoder_root.find("./decoder[@name='sentrix']")
    assert decoder is not None
    assert decoder.findtext("parent") == "json"
    assert decoder.findtext("use_own_name") == "true"
    assert decoder.findtext("plugin_decoder") == "JSON_Decoder"
    assert decoder.find("prematch") is not None
    assert decoder.find("regex") is None

    rules = ET.parse(ROOT / "wazuh" / "rules" / "local_rules.xml").getroot()
    assert rules.attrib["name"] == "sentrix,physical_intrusion,"
    rule_fields = {field.attrib["name"] for field in rules.findall(".//field")}
    assert {"source", "class", "confidence_level", "pacs_event_status"} <= rule_fields


def test_rule_ids_and_correlation_references_are_stable() -> None:
    rules = ET.parse(ROOT / "wazuh" / "rules" / "local_rules.xml").getroot()
    by_id = {rule.attrib["id"]: rule for rule in rules.findall("rule")}

    assert by_id["100201"].attrib["level"] == "10"
    assert by_id["100202"].attrib["level"] == "12"
    assert by_id["100203"].attrib["level"] == "12"
    assert by_id["100210"].findtext("if_sid") == "5712,5763"
    assert by_id["100211"].attrib == {
        "id": "100211",
        "level": "14",
        "timeframe": "120",
    }
    assert by_id["100211"].findtext("if_sid") == "100201"
    assert by_id["100211"].findtext("if_matched_sid") == "100210"


def test_mapper_rejects_subthreshold_confidence_labeled_high() -> None:
    source = load_sample(SAMPLES / "high_confidence_intrusion.json")
    source["confidence"] = 0.8999
    source["confidence_level"] = "high"

    with pytest.raises(
        AlertValidationError,
        match=r"confidence_level must be 'borderline' for confidence 0\.8999",
    ):
        to_wazuh(source)


def test_wazuh_compose_pins_tested_manager_and_mounts_custom_xml() -> None:
    compose = (ROOT / "wazuh" / "docker-compose.yml").read_text(encoding="utf-8")

    assert "image: wazuh/wazuh-manager:4.14.5" in compose
    assert (
        "./decoders/local_decoder.xml:/var/ossec/etc/decoders/local_decoder.xml:ro"
        in compose
    )
    assert "./rules/local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro" in compose
