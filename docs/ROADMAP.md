# Roadmap (v0.1 → v1.0)

| Tier | Version | Focus | Key deliverables | Exit criteria |
|---|---|---|---|---|
| 0 | v0.1 | Core capture & pipeline | ESP32 firmware, raw ingest, basic visualization | Reliable CSI stream from ≥1 node reaches the collector |
| 1 | v0.2–v0.3 | Baseline detection | Feature extraction, Random Forest baseline | Reproducible benchmark report published, however unflattering |
| 2 | v0.4–v0.5 | Security hardening | mTLS enrollment/rotation, hash-chained log | No unauthenticated node can inject data; tamper-evidence verified |
| 3 | v0.6–v0.7 | SOC + explainability | XGBoost option, SHAP, Wazuh decoders/rules, OCSF output | Alerts show up, explained, inside a real Wazuh instance |
| 4 | v0.8–v0.9 | Independent verification + dataset | Verifier CLI, OpenTimestamps anchoring, labeled dataset live on Zenodo with DOI | A third party can verify a log without running Sentrix itself |
| 5 | v1.0 | Credibility push | Full docs, published threat model, Arsenal/DFRWS submission-ready | External reviewer feedback incorporated |

## Rigor checklist (apply at every ML-affecting milestone)

- [ ] Never report same-room train/test accuracy as the headline number
- [ ] Explicitly audit train/test splits for subject/session leakage
- [ ] Report leave-one-room-out and leave-one-device-out accuracy, not just in-distribution accuracy
- [ ] Publish confusion matrices and per-environment breakdowns, not a single aggregate number
- [ ] Re-validate after any hardware or firmware revision

## Visibility strategy (sequenced)

1. GitHub hygiene — README with demo GIF, architecture diagram, honest per-environment metrics
2. Black Hat Arsenal submission (once mTLS + forensic logging work end-to-end)
3. DEF CON demo labs / BSides talks
4. DFRWS practitioner track, later a full paper in *Forensic Science International: Digital Investigation*
5. Zenodo dataset release with DOI
6. arXiv preprint on the hash-chain + SHAP evidentiary design
7. Submit the Wazuh ruleset upstream / list in Wazuh community integrations
8. PRs into relevant awesome-lists once the repo is demo-ready

Full research context, competitive landscape, and citation list: see the project's research roadmap document (kept alongside this repo's planning materials, not duplicated here to avoid drift between the two).
