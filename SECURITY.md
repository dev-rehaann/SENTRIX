# Security Policy

Sentrix is a physical-intrusion detection tool with a forensic-evidence chain — vulnerabilities here have unusually direct real-world consequences (a bypassed sensor is a physical security failure, not just a software bug). We take reports seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities privately via one of:
- GitHub Security Advisories ("Report a vulnerability" under this repo's Security tab), or
- A private email to the maintainer (add contact address once finalized)

Include, where possible:
- Affected component (`firmware/`, `collector/`, `pipeline/`, `forensics/`, `verifier-cli/`, `soc-integration/`)
- Steps to reproduce
- Impact assessment (e.g. "allows unauthenticated node injection," "breaks hash-chain integrity")
- Any suggested mitigation

## Scope

Particularly high-priority areas:
- mTLS enrollment / certificate validation in `collector/`
- Hash-chain integrity and signature verification in `forensics/` and `verifier-cli/`
- OpenTimestamps anchoring logic
- Any path where an unauthenticated actor could inject, suppress, or alter sensor data or log entries

## Response

This is currently a single-maintainer project. Best-effort acknowledgment target is within 5 business days. Coordinated disclosure is preferred — please allow time for a fix before public disclosure.

## Out of scope

General bugs with no security impact should go through normal GitHub issues instead.
