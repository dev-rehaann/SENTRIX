# Threat Model

Vestrix assumes an attacker can attempt any of the following. Every security control in the project should map back to one of these four categories — if a proposed feature doesn't map to one, question whether it belongs in the security layer at all.

| # | Attacker capability | Mitigation | Where |
|---|---|---|---|
| a | Physically tamper with or replace a sensor node | Tamper switch on sensor enclosures, feeding its own hash-chained "sensor tamper" event type. Physical tampering becomes forensic evidence itself. | `firmware/`, `forensics/` |
| b | Attempt to spoof CSI data over the network (inject fabricated "all clear" readings) | Mutual TLS between every node and the collector — the single highest-leverage control in the project. No unauthenticated node can inject data. | `collector/` (mTLS enrollment) |
| c | Attempt to alter stored logs after the fact | SHA-256 hash-chained, append-only event log; periodic OpenTimestamps (Bitcoin-anchored) checkpoints; independent verifier CLI in a separate codebase | `forensics/`, `verifier-cli/` |
| d | Attempt to suppress or delay alerts | Baseline drift monitoring, sensor heartbeat/liveness checks, correlation rule (Wazuh) for "sensor tamper event correlated with alert suppression" | `pipeline/` (drift monitor), `soc-integration/wazuh/` |

## Documented, category-level limitations

Consistent with the project's honest-benchmarking principle, these are stated plainly rather than glossed over:

- **Environmental drift.** Furniture moves, temperature/humidity shifts, and neighboring WiFi churn degrade accuracy over time. Mitigated by a baseline drift monitor and scheduled re-calibration, logged as its own event type — not eliminated.
- **Cross-domain failure.** Models trained in one room/device often fail in another. This is a well-established open problem in the CSI sensing literature, not a bug introduced by Vestrix. Mitigated by leave-one-room-out / leave-one-device-out validation and documented per-environment accuracy (see `ml/benchmarks/`).
- **Adversarial evasion.** Published research documents context-aware spoofing, metasurface-based signal manipulation, and CSI-targeted adversarial perturbation attacks against WiFi-based sensing. Vestrix documents this as a known, published limitation class and does not claim adversarial robustness that hasn't been tested.
- **Fundamental sensing limits.** Motion-based sensing (WiFi, PIR, ultrasonic alike) has well-known limitations around very slow or minimal movement. This is standard, expected disclosure for any motion-based sensor, not a vulnerability unique to Vestrix.

## Out of scope for this document

Specific exploit engineering details do not belong in user-facing docs. This document stays at the category level intentionally — enough for an integrator or auditor to understand what's defended against and what isn't, without functioning as an attack cookbook.

## Standards mapping

Physical-layer events detected by Vestrix (presence, movement, sensor tamper) map to relevant MITRE ATT&CK physical-access techniques and CAPEC physical-security attack patterns. Keep this mapping current in `docs/standards-alignment.md`.
