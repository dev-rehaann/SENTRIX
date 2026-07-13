# Standards Alignment

Wherever an existing standard already covers a design area, Vestrix maps to it instead of inventing something bespoke.

| Standard / body of work | What it gives Vestrix | Where it applies |
|---|---|---|
| Schneier & Kelsey (1999); Crosby & Wallach (USENIX Security '09) | Canonical hash-chain / Merkle-tree tamper-evident logging design | `forensics/` |
| NIST SP 800-86 | Four-phase forensic process: collection → examination → analysis → reporting | Overall evidence pipeline design |
| ISO/IEC 27037 | Evidence identification, collection, acquisition, preservation best practice | Chain-of-custody documentation |
| ISO/IEC 27041–27043 | Investigative method adequacy, evidence analysis/interpretation, incident investigation process | Documentation and reporting |
| OpenTimestamps | Free, decentralized, Bitcoin-anchored proof-of-existence | Periodic checkpoint anchoring |
| OCSF (Linux Foundation) | Vendor-neutral security event schema | `soc-integration/ocsf/` |
| MITRE ATT&CK / CAPEC ("Physical" category) | Existing (if thin) coverage of physical attack patterns | Physical-access event mapping; basis for a future physical-intrusion taxonomy contribution |
| Daubert / Frye standards, FRE 602/403, proposed FRE 707 | Known/testable error rates and explainability requirements for algorithmic evidence | Justifies Random Forest / XGBoost + SHAP over black-box deep models (`ml/`) |
| GDPR Art. 35, EU AI Act 2024/1689 | DPIA required for systematic monitoring; workplace monitoring AI treated as high-risk | Responsible-use / DPIA template (planned, Tier 4) |
| IEEE 802.11bf (ratified 2024) | Standardizes WiFi sensing across chipsets; lists security/privacy as a design consideration | Long-term hardware-portability roadmap |

## Prior art acknowledgment

Vestrix does not claim novelty in WiFi CSI sensing, ESP32 CSI extraction, or ML-classified presence detection. Relevant prior art includes:

- ESP32-CSI-Tool (Hernandez & Bulut) — https://github.com/StevenMHernandez/ESP32-CSI-Tool
- esp-csi (Espressif, official) — https://github.com/espressif/esp-csi
- ESPectre (F. Pace) — https://github.com/francescopace/espectre
- RuView — https://github.com/ruvnet/ruview (closest open competitor by breadth; reference point, not a target to imitate)

See `docs/NON-GOALS.md` for how this shapes project scope, and the project roadmap for the full reference list used during planning.
