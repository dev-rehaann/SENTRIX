# Contributing to Sentrix

Thanks for considering a contribution. Sentrix is a single-maintainer, fully open project right now — no restricted tiers, no closed modules — and the governance model is intentionally simple until there's a recurring set of outside contributors.

## Ground rules

1. **Honesty over polish.** If you're contributing a benchmark, a detection result, or an accuracy claim, it must be reproducible from a documented dataset and script. Hand-reported numbers without a reproduction path will be asked to be redone before merge.
2. **Security-first defaults.** Changes to the sensor↔collector transport, the hash-chain logger, or the verifier CLI get extra scrutiny — these are the parts of the project the forensic-grade claim depends on.
3. **Keep the verifier CLI independent.** Do not add a dependency from `verifier-cli/` on any other package in this repo. It must remain auditable as a standalone, minimal codebase.
4. **Scope discipline.** Sentrix is intentionally narrow (see `docs/NON-GOALS.md`). Feature requests that broaden scope into general-purpose WiFi sensing (gesture recognition, vitals, etc.) will likely be declined unless they directly serve intrusion detection.

## Environment setup

See `docs/GETTING_STARTED.md` for the full toolchain setup (ESP-IDF + Python).

## How to contribute by area

- **Firmware (`firmware/`)** — ESP-IDF component changes; test against real ESP32 hardware before submitting, note which board revision you tested on.
- **Pipeline / ML (`pipeline/`, `ml/`)** — any accuracy claim needs a leave-one-room-out or leave-one-device-out result, not just in-distribution accuracy. Update `ml/benchmarks/` with a new dated file rather than overwriting the previous one.
- **Forensics (`forensics/`, `verifier-cli/`)** — changes to the record schema are backwards-compatibility-sensitive; flag schema changes explicitly in your PR description.
- **SOC integration (`soc-integration/`)** — validate Wazuh rule changes with `wazuh-logtest` and include the test output in your PR. OCSF mapping changes should note which OCSF class/version you targeted.
- **Docs (`docs/`)** — corrections and clarity improvements are always welcome, no need to open an issue first.

## Pull requests

- Keep PRs scoped to one area where possible.
- Describe what you tested and how (hardware used, dataset used, Wazuh version, etc.).
- New benchmark numbers must include methodology, not just a headline figure.

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. Security vulnerabilities should **not** be filed as public issues — see `SECURITY.md`.

## Code of conduct

By participating, you agree to abide by `CODE_OF_CONDUCT.md`.
