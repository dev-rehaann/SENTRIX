# Sample-event validation

Run these commands from `soc-integration/` after installing the decoder and
rules on a Wazuh manager. Each input file is a canonical alert; the mapper
produces the flat JSON line consumed by `sentrix_json`.

Positive cases use Wazuh's `-U rule-id:level:decoder` assertion, so a mismatch
causes a non-zero exit:

```console
python3 -m ocsf.mapper wazuh wazuh/sample_events/high_confidence_intrusion.json | sudo /var/ossec/bin/wazuh-logtest -q -U 100201:10:sentrix_json
python3 -m ocsf.mapper wazuh wazuh/sample_events/intrusion_without_badge.json | sudo /var/ossec/bin/wazuh-logtest -q -U 100202:12:sentrix_json
python3 -m ocsf.mapper wazuh wazuh/sample_events/sensor_tamper.json | sudo /var/ossec/bin/wazuh-logtest -q -U 100203:12:sentrix_json
```

The remaining samples are negative cases. Use verbose output and confirm phase
2 selects `sentrix_json`, while phase 3 reports no alerting Sentrix rule (the
level-0 grouping rule `100200` may be shown):

```console
python3 -m ocsf.mapper wazuh wazuh/sample_events/borderline_intrusion.json | sudo /var/ossec/bin/wazuh-logtest -v
python3 -m ocsf.mapper wazuh wazuh/sample_events/low_confidence_intrusion.json | sudo /var/ossec/bin/wazuh-logtest -v
python3 -m ocsf.mapper wazuh wazuh/sample_events/normal_benign.json | sudo /var/ossec/bin/wazuh-logtest -v
```

`intrusion_without_badge.json` assumes an upstream PACS enricher has already
closed its correlation window and set `pacs_event_status` to `missing`. The
rules do not infer the absence of a badge event from these samples.
