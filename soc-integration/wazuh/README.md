# Wazuh integration

These files target the current Wazuh 4.x XML decoder/rule syntax. The decoder
uses a narrow prematch only for routing and `JSON_Decoder` for all field
extraction.

## Install on a Wazuh manager

Back up and merge with existing local files rather than overwriting unrelated
customizations:

```console
sudo cp /var/ossec/etc/decoders/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml.bak
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
sudo install -m 0640 wazuh/decoders/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml
sudo install -m 0640 wazuh/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

The commands assume the shell is in `soc-integration/`. On a manager with
existing custom rules, manually merge the `<decoder>` and `<group>` blocks
instead of using `install`.

## Test every sample

Each command maps the canonical sample through the same Python Wazuh mapper
used by producers and feeds one compact JSON line to Wazuh. For positive
cases, `-U rule-id:level:decoder` makes `wazuh-logtest` exit successfully only
when the exact expected rule, level, and decoder match:

```console
python3 -m ocsf.mapper wazuh wazuh/sample_events/high_confidence_intrusion.json | sudo /var/ossec/bin/wazuh-logtest -q -U 100201:10:sentrix_json
python3 -m ocsf.mapper wazuh wazuh/sample_events/intrusion_without_badge.json | sudo /var/ossec/bin/wazuh-logtest -q -U 100202:12:sentrix_json
python3 -m ocsf.mapper wazuh wazuh/sample_events/borderline_intrusion.json | sudo /var/ossec/bin/wazuh-logtest -v
python3 -m ocsf.mapper wazuh wazuh/sample_events/low_confidence_intrusion.json | sudo /var/ossec/bin/wazuh-logtest -v
python3 -m ocsf.mapper wazuh wazuh/sample_events/sensor_tamper.json | sudo /var/ossec/bin/wazuh-logtest -q -U 100203:12:sentrix_json
python3 -m ocsf.mapper wazuh wazuh/sample_events/normal_benign.json | sudo /var/ossec/bin/wazuh-logtest -v
```

Expected final rules:

| Sample | Expected result |
|---|---|
| `high_confidence_intrusion.json` | `100201`, level 10 |
| `intrusion_without_badge.json` | `100202`, level 12 |
| `borderline_intrusion.json` | no alerting Sentrix rule (only level-0 grouping rule `100200`) |
| `low_confidence_intrusion.json` | no alerting Sentrix rule (only `100200`) |
| `sensor_tamper.json` | `100203`, level 12 |
| `normal_benign.json` | no alerting Sentrix rule (negative test; only `100200`) |

`wazuh-logtest` prints decoding in phase 2 and the selected rule in phase 3.
Confirm phase 2 reports decoder `sentrix_json` and fields such as `source`,
`class`, `confidence_level`, and `pacs_event_status`.

## Authentication correlation assumption

Rule `100210` wraps two current built-in OpenSSH brute-force detections:

- `5712`: brute force using nonexistent users.
- `5763`: brute force following repeated SSH authentication failures.

Rule `100211` fires at level 14 when a high-confidence Sentrix intrusion
arrives within 120 seconds after either built-in rule. This is intentionally
illustrative until a real authentication source is enriched with `site_id` or
`zone_id`; as shipped, the time correlation is manager-global and does not
claim both events concern the same site.

To exercise the correlation in one persistent `wazuh-logtest` session, start:

```console
sudo /var/ossec/bin/wazuh-logtest -v
```

Then submit enough same-source OpenSSH failure lines to trigger built-in rule
`5712` or `5763`, followed within 120 seconds by the mapped
`high_confidence_intrusion.json` line. Wazuh correlation state is session-local
in `wazuh-logtest`; separate one-shot commands do not share it.

## PACS assumption

`pacs_event_status`, `pacs_reader_id`, and `pacs_event_id` are placeholder
fields for a future badge/PACS enricher. Rule `100202` only consumes an
upstream, finalized `missing` status. It does not infer the absence of an event.

## Wazuh references

The integration follows Wazuh's documented
[JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html),
[decoder XML syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html),
[rule XML syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html),
and [`wazuh-logtest` options](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html).
Wazuh's JSON decoder does not support arrays of objects, so the mapper emits
the leading SHAP entry as the scalar `shap_top_feature` and `shap_top_value`
fields instead of sending canonical `top_shap` directly.
