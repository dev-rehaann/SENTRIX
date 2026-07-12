# Non-Goals — Explicit Scope Boundaries

This list is maintained deliberately, not deleted as the project matures. A
living non-goals list is part of the credibility story: RuView lost
credibility retracting an inflated "100% detection" claim; a public,
maintained non-goals section is the antidote.

## What Sentrix is not trying to be

- **Not** matching RuView's ~105-module breadth. Depth in one defensible
  niche (security + forensics + SOC integration) beats breadth across many
  shallow ones.
- **Not** a general-purpose WiFi sensing research platform. Gesture
  recognition, vital-signs sensing, pose estimation, etc. stay out of scope
  unless they directly serve intrusion detection.
- **Not** claiming production maturity that hasn't been earned. Every
  benchmark shipped is real, dated, reproducible — including on the days the
  numbers aren't flattering.
- **Not** claiming novelty in WiFi CSI sensing, ESP32 CSI extraction, or
  ML-classified presence detection. All of that is prior art (10+ years of
  academic work; ESPectre already does open-source CSI motion sensing for
  smart homes). Sentrix's claim is narrower: the integration of security-first
  design, forensic chain-of-custody, and native SOC/SIEM correlation around
  that sensing — a combination that doesn't exist elsewhere, open or
  commercial.
- **Not** claiming adversarial robustness that hasn't been tested. Known
  published attack classes (context-aware spoofing, metasurface-based signal
  manipulation, CSI-targeted adversarial perturbation) are documented as
  known limitations, not solved problems.

## Revisit triggers

This file should be revisited (not silently dropped) when:
- A release adds a capability that could be mistaken for scope creep
- A benchmark result would look better if a caveat here were quietly removed
  — if that temptation shows up, that's the signal the file is doing its job
