# Sample-event validation

Run from `soc-integration/` after starting the manager with the steps in
[`../README.md`](../README.md). Each command maps one canonical alert and uses
`-U` to assert the exact rule ID, level, and decoder against the running Wazuh
4.14.5 manager:

```console
python3 -m ocsf.mapper wazuh wazuh/sample_events/high_confidence_intrusion.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100201:10:sentrix
python3 -m ocsf.mapper wazuh wazuh/sample_events/intrusion_without_badge.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100202:12:sentrix
python3 -m ocsf.mapper wazuh wazuh/sample_events/borderline_intrusion.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100200:0:sentrix
python3 -m ocsf.mapper wazuh wazuh/sample_events/low_confidence_intrusion.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100200:0:sentrix
python3 -m ocsf.mapper wazuh wazuh/sample_events/sensor_tamper.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100203:12:sentrix
python3 -m ocsf.mapper wazuh wazuh/sample_events/normal_benign.json | docker compose -f wazuh/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/wazuh-logtest -U 100200:0:sentrix
```

All commands must end with `Unit test OK`. Rule `100200` is level 0 and does
not generate an alert; it groups and suppresses borderline, low-confidence,
and benign events. The benign sample is therefore a successful negative test
when it selects only `100200` and has no `**Alert to be generated.` line.

[`logtest_output.txt`](logtest_output.txt) contains the actual output excerpts,
image digest, and mounted-file hashes captured from the live manager run.
`intrusion_without_badge.json` assumes an upstream PACS enricher has already
set `pacs_event_status` to `missing`; Wazuh does not infer absence itself.
