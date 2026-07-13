# Vestrix SOC alert schema, version 1.0

This document is the single source of truth for Vestrix SOC alerts. Producers
create one canonical internal dictionary; `ocsf/mapper.py` derives both the
Wazuh JSON event and the OCSF event from that dictionary. Wazuh and OCSF are not
independent schemas.

## Canonical dictionary

Unknown keys are rejected. Required nullable fields must be present even when
their value is `null`. Optional evidence-link fields may be absent.

| Field | JSON type | Required | Source and rule |
|---|---|---:|---|
| `schema_version` | string | yes | SOC contract version; exactly `1.0`. This is not collector `schema_version=0.1`. |
| `source` | string | yes | Routing discriminator; exactly `vestrix`. |
| `event_id` | string | yes | Stable SOC alert ID generated at alert creation. A producer may derive it from `record_hash` when available. |
| `ts_utc` | string | yes | Directly from forensic `ts_utc`; collector `timestamp_utc` must be renamed at the collector-to-forensics boundary. RFC 3339 UTC ending in `Z`. |
| `node_id` | string | yes | Direct from collector and forensics `node_id`. |
| `site_id` | string | yes | Deployment-inventory enrichment used for SOC correlation; not currently present in collector/forensics. |
| `zone_id` | string | yes | Deployment-inventory enrichment identifying the protected physical zone. |
| `class` | string | yes | Direct from forensic `class`. SOC v1 accepts `intrusion`, `normal`, or `sensor_tamper`. `sensor_tamper` is the planned hardware-switch event named in the threat model; the current collector does not emit it yet. |
| `confidence` | number | yes | Direct from forensic `confidence`, finite and in `[0,1]`. A deterministic tamper switch uses `1.0`. |
| `confidence_level` | string | yes | Derived from `confidence`: `high` for `>=0.90`, `borderline` for `>=0.60`, otherwise `low`. The mapper rejects inconsistent values. |
| `model_id` | string | yes | Direct from forensic `model_id`; tamper events use the detector ID such as `sensor-tamper-switch-v1`. |
| `top_shap` | array of objects | yes | Narrow SOC projection of forensic `top_shap`. Each object has `feature` (string), `value` (finite number), and optional positive `rank` (integer). Empty for non-ML events. |
| `pacs_event_status` | string | yes | PACS enrichment: `matched`, `missing`, `unknown`, or `not_applicable`. See the placeholder contract below. |
| `pacs_reader_id` | string or null | yes | Illustrative PACS reader ID. Required non-null when status is `matched`; may identify the expected reader when status is `missing`. |
| `pacs_event_id` | string or null | yes | Illustrative badge-event ID. Required non-null only when status is `matched`. |
| `csi_window_sha256` | 64-char lowercase hex string | no | Direct collector correlation pointer. It is deliberately not duplicated under `raw_csi_hash`. |
| `sequence_number` | non-negative integer | no | Direct collector `sequence_number`; transport/replay correlation only. |
| `seq` | non-negative integer | no | Direct forensic chain `seq`; not the collector sequence number. |
| `record_hash` | 64-char lowercase hex string | no | Direct forensic `record_hash`, retained as the evidence-chain lookup pointer. |

### Naming conflict that must be resolved upstream

The current collector emits `timestamp_utc`, `sequence_number`, and
`csi_window_sha256`. The forensic record expects `ts_utc`, `seq`, and
`raw_csi_hash`. Only the timestamp mapping is unambiguous. The repository does
not yet normatively state that `csi_window_sha256 == raw_csi_hash`, and the two
sequence fields have different domains (per-sensor transport versus global
forensic chain). This SOC schema therefore:

- uses forensic `ts_utc` as its event time;
- keeps `sequence_number` and `seq` distinct;
- keeps optional `csi_window_sha256` for collector correlation;
- omits `raw_csi_hash`, `features_hash`, `model_config_hash`, `prev_hash`, and
  `signature` because SOC alerts are not forensic-record replicas;
- keeps only `record_hash` as the forensic evidence lookup pointer.

An upstream integration must explicitly establish the `csi_window_sha256` to
`raw_csi_hash` relationship before either name is substituted for the other.

## PACS placeholder contract

PACS integration is illustrative until a badge/access-control source is wired
in. An external correlation/enrichment step, not the Wazuh rule, must set:

- `pacs_event_status=matched` when a badge event for the same site/zone exists
  in the configured access window; both PACS IDs are then non-null.
- `pacs_event_status=missing` after that window closes with no matching event;
  `pacs_event_id` is null and `pacs_reader_id` may name the expected reader.
- `unknown` while correlation cannot be completed.
- `not_applicable` for normal and sensor-tamper events.

The Wazuh missing-badge rule trusts this upstream status; it does not attempt
negative event correlation inside Wazuh.

## Wazuh JSON derivation

`to_wazuh()` validates the canonical dictionary, copies all non-null scalar
fields, and replaces the potentially complex `top_shap` array with two stable
dynamic fields:

- `shap_top_feature` (string, `none` when empty)
- `shap_top_value` (number, `0.0` when empty)

The JSON decoder routes on `source`, and rules use `class`,
`confidence_level`, `pacs_event_status`, `site_id`, `zone_id`, and `node_id`.
No regex is used to extract JSON fields.

## OCSF derivation and class choice

The target is **OCSF 1.8.0 Detection Finding**, Findings category:

- `category_uid = 2` (Findings)
- `class_uid = 2004` (Detection Finding)
- `activity_id = 1` (Create)
- `type_uid = 200401`

Detection Finding is the closest core class because OCSF defines it for
detections or alerts generated by security products using detection engines,
correlation engines, or other methodologies. Vestrix is an ML/physical-sensing
detection engine. `Incident Finding` is not used because a raw Vestrix alert has
not yet entered an incident-management workflow. There is no core OCSF physical
intrusion event class, so Vestrix-specific physical context is retained under
the standard `unmapped.vestrix` object rather than invented as top-level OCSF
attributes.

The mapper populates every required Detection Finding/base-event field:
`activity_id`, `category_uid`, `class_uid`, `finding_info.uid`, `metadata`
(including required `metadata.product` and `metadata.version`), `severity_id`,
`time`, and `type_uid`. It also supplies recommended classification names,
status, confidence, analytic/model details, the sensor as `device`, and
`is_alert`. OCSF `confidence_score` is the integer percentage `0..100`; the
canonical binary64 remains available under `unmapped.vestrix.confidence`.

References: the OCSF 1.8.0 `detection_finding`, `finding`, `base_event`,
`finding_info`, and `metadata` definitions at <https://schema.ocsf.io/>.
