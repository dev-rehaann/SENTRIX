# Getting Started

## 1. Environment

```bash
# Firmware toolchain
git clone -b v5.x https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh && . ./export.sh

# Python side
python3 -m venv .venv && source .venv/bin/activate
pip install numpy scipy pandas scikit-learn xgboost shap cryptography
```

## 2. First node

```bash
idf.py create-project vestrix-node
# wire in CSI capture in firmware/main/
idf.py -p /dev/ttyUSB0 flash monitor
```

Confirm raw frames reach a throwaway dev collector first — no security yet, just prove the pipeline works end to end.

## 3. mTLS

Stand up the project CA (see `docs/architecture.md` and the `openssl` commands below), issue a node certificate, and require the collector to reject anything unsigned.

```bash
# Minimal project CA — a starting point, not production-hardened
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -days 3650 -out ca.crt -subj "/CN=Vestrix Root CA"

# Per-node certificate
openssl genrsa -out node-07.key 2048
openssl req -new -key node-07.key -out node-07.csr -subj "/CN=node-07"
openssl x509 -req -in node-07.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out node-07.crt -days 365
```

## 4. Processing + baseline ML

Build the feature-extraction module in `pipeline/`, train a Random Forest baseline on a small labeled set, and publish the first (honest, likely rough) `ml/benchmarks/BENCHMARKS.md`.

## 5. Forensic logging

Implement the hash chain in `forensics/`, wire in an OpenTimestamps client for periodic anchoring.

## 6. SOC integration

Write the first Wazuh decoder + rule in `soc-integration/wazuh/`, add the OCSF mapper in `soc-integration/ocsf/` off the same internal alert schema.

## 7. Verifier CLI

Build the independent verifier in `verifier-cli/` as its own codebase: chain integrity + timestamp check, nothing else, no shared dependencies with the rest of the repo.

## 8. Tests + CI

Unit tests for hash-chain integrity are non-negotiable. See `.github/workflows/ci.yml` for the baseline lint + test pipeline.

## 9. Docs

README, architecture diagram, threat model, standards alignment — all before the public v0.1 tag, not after.

## 10. Dataset + visibility

Record labeled intrusion scenarios, publish to Zenodo with a DOI once the labeling methodology is solid enough to trust. See `docs/ROADMAP.md` §16 for the full visibility strategy.
