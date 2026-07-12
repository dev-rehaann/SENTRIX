# Wazuh integration

These files are live-tested against the official
`wazuh/wazuh-manager:4.14.5` image. The decoder uses a narrow prematch only for
routing and `JSON_Decoder` for all field extraction.

The Compose stack is intentionally manager-only. The official single-node
quickstart also starts an indexer and dashboard, but neither participates in
`wazuh-logtest`. Filebeat/indexer connection warnings are therefore expected
in container logs and do not affect the manager analysis engine or these tests.

## Docker verification

Run all commands from `soc-integration/`. Docker Compose v2 and Python 3.11 or
newer are required.

### 1. Start the manager

```console
docker compose -f wazuh/docker-compose.yml up -d --wait
docker compose -f wazuh/docker-compose.yml ps
```

The second command must report `wazuh.manager` as `healthy`. Compose mounts
`wazuh/decoders/local_decoder.xml` and `wazuh/rules/local_rules.xml` read-only
at `/var/ossec/etc/decoders/local_decoder.xml` and
`/var/ossec/etc/rules/local_rules.xml` in the container.

### 2. Assert all six samples with `wazuh-logtest -U`

`-U rule-id:level:decoder` makes `wazuh-logtest` return non-zero unless all
three expected values match. These are the exact commands used for the saved
evidence:

```console
python3 -m ocsf.mapper wazuh wazuh/sample_events/high_confidence_intrusion.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100201:10:sentrix
python3 -m ocsf.mapper wazuh wazuh/sample_events/intrusion_without_badge.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100202:12:sentrix
python3 -m ocsf.mapper wazuh wazuh/sample_events/borderline_intrusion.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100200:0:sentrix
python3 -m ocsf.mapper wazuh wazuh/sample_events/low_confidence_intrusion.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100200:0:sentrix
python3 -m ocsf.mapper wazuh wazuh/sample_events/sensor_tamper.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100203:12:sentrix
python3 -m ocsf.mapper wazuh wazuh/sample_events/normal_benign.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100200:0:sentrix
```

Expected final rules:

| Sample | Expected result |
|---|---|
| `high_confidence_intrusion.json` | `100201`, level 10, alert |
| `intrusion_without_badge.json` | `100202`, level 12, alert |
| `borderline_intrusion.json` | only non-alerting grouping rule `100200`, level 0 |
| `low_confidence_intrusion.json` | only non-alerting grouping rule `100200`, level 0 |
| `sensor_tamper.json` | `100203`, level 12, alert |
| `normal_benign.json` | negative test: only `100200`, level 0; no alert |

Every command must end with `Unit test OK`. A level-0 `100200` match means the
event was decoded and deliberately suppressed; it is not an alert. Alerting
output additionally contains `**Alert to be generated.`.

### 3. Capture evidence

On Bash, rerun the same commands as a group and save their complete combined
stdout/stderr with `tee`:

```console
set -o pipefail
{
  echo '=== high_confidence_intrusion.json ==='
  python3 -m ocsf.mapper wazuh wazuh/sample_events/high_confidence_intrusion.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100201:10:sentrix
  echo '=== intrusion_without_badge.json ==='
  python3 -m ocsf.mapper wazuh wazuh/sample_events/intrusion_without_badge.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100202:12:sentrix
  echo '=== borderline_intrusion.json ==='
  python3 -m ocsf.mapper wazuh wazuh/sample_events/borderline_intrusion.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100200:0:sentrix
  echo '=== low_confidence_intrusion.json ==='
  python3 -m ocsf.mapper wazuh wazuh/sample_events/low_confidence_intrusion.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100200:0:sentrix
  echo '=== sensor_tamper.json ==='
  python3 -m ocsf.mapper wazuh wazuh/sample_events/sensor_tamper.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100203:12:sentrix
  echo '=== normal_benign.json (negative test) ==='
  python3 -m ocsf.mapper wazuh wazuh/sample_events/normal_benign.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100200:0:sentrix
} 2>&1 | tee wazuh/sample_events/logtest_output.txt
```

The checked-in
[`sample_events/logtest_output.txt`](sample_events/logtest_output.txt) records
the actual decoder, final rule, level, alert status, image digest, and mounted
file hashes from the live verification run. Stop the manager when finished:

```console
docker compose -f wazuh/docker-compose.yml down
```

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
