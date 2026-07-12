# OCSF mapper

`mapper.py` validates the canonical dictionary in `../SCHEMA.md` and maps it
to OCSF 1.8.0 Detection Finding (`class_uid=2004`) or to the Wazuh JSON shape.

From `soc-integration/`:

```console
python -m ocsf.mapper ocsf wazuh/sample_events/high_confidence_intrusion.json
python -m ocsf.mapper wazuh wazuh/sample_events/high_confidence_intrusion.json
pytest
```

The module has no runtime dependency outside Python 3.11 or newer.
