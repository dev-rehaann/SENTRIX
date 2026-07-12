# Sentrix independent verifier

`sentrix-verify` is a small, read-only Rust verifier for the Sentrix forensic
JSONL chain format. It is a separate codebase from the collector and Python
forensics pipeline. Its contract is the published `CHAIN_FORMAT.md`, not any
Sentrix implementation.

## Build and test

Install a stable Rust toolchain, then run:

```console
cd verifier-cli
cargo build --release
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

The binary is `target/release/sentrix-verify` (or `.exe` on Windows).

Dependencies are intentionally narrow: `serde`/`serde_json` parse untrusted
JSON, `sha2` computes record and OTS operation hashes, `ed25519-dalek` verifies
signatures, and `clap` parses the CLI. The only additional runtime dependency is
`ryu`; it supplies shortest-round-trip binary64 digits so the small canonical
serializer can reproduce CPython's required float spelling.

## Chain verification

```console
sentrix-verify chain evidence/chain.jsonl --pubkey keys/logger-public.hex
```

The public-key file may contain exactly 32 raw Ed25519 public-key bytes, or 64
lowercase hexadecimal characters with an optional final LF. The command checks
every physical line in order: strict UTF-8 and JSON, exact schema and value
constraints, canonical stored bytes, sequence and previous-hash linkage,
SHA-256 `record_hash`, and Ed25519 signature. It exits 0 only when every record
passes. An empty file is a valid empty chain but has no tip.

On failure it exits non-zero and writes one deterministic diagnostic such as:

```text
chain verification failed at seq 17: record_hash mismatch
```

## OpenTimestamps anchor status

```console
sentrix-verify anchor evidence/chain.jsonl --ots-proof evidence/tip.ots
```

This release implements a deliberately limited, offline Bitcoin proof subset.
It checks that the detached OTS envelope uses SHA-256, that its digest is the
current chain tip's raw 32-byte `record_hash`, and that append/prepend/SHA-256
proof paths reach a Bitcoin block-header attestation. Unsupported operations,
pending-only timestamps, malformed proofs, and digest mismatches fail closed.
The anchor command reads only the canonical final record; run `chain` with the
logger public key first to authenticate the complete chain.

Full Bitcoin anchoring is **stubbed and never reported as success**. A standard
`.ots` proof stores a block height but not the authoritative block header or
evidence that the header belongs to Bitcoin's best chain. The requested two
file inputs therefore cannot independently establish that last fact. When tip
binding reaches a Bitcoin attestation, this command exits non-zero and says
that block-header/best-chain verification is not implemented. It never turns a
calendar response or an unauthenticated public web API into a forensic pass.

## What this tool does not do

- It does not connect to or control the Sentrix collector.
- It does not import, execute, or trust any other Sentrix component.
- It does not repair, rewrite, append, delete, or otherwise modify evidence.
- It does not decide whether signed event contents are factually correct.
- It does not claim a fully verified Bitcoin timestamp in this release.

## License

Apache License 2.0, as declared in `Cargo.toml` and the repository's root
`LICENSE` file.
