# Sentrix forensic chain format, version 1

This document is the normative, byte-level specification for the first Sentrix
forensic chain format. A verifier does not need any Sentrix writer code to
implement it. There is no version field in version 1; deployments must associate
this specification with the chain out of band.

## Record schema

Every JSON record has exactly these fields and no others:

| Field | JSON type | Rule |
|---|---|---|
| `seq` | integer | Zero-based sequence, in `0..2^63-1` |
| `ts_utc` | string | RFC 3339 UTC timestamp in `YYYY-MM-DDTHH:MM:SS[.fraction]Z` form |
| `node_id` | string | Non-empty logger/node identifier |
| `raw_csi_hash` | string | 64 lowercase hexadecimal characters |
| `features_hash` | string | 64 lowercase hexadecimal characters |
| `model_id` | string | Non-empty model identifier |
| `model_config_hash` | string | 64 lowercase hexadecimal characters |
| `class` | string | Non-empty classification label |
| `confidence` | number | Finite number in the closed interval `[0,1]`; booleans are not numbers |
| `top_shap` | JSON value | JSON-compatible explanation data under the restrictions below |
| `prev_hash` | string | Previous record's `record_hash`, or the genesis sentinel |
| `record_hash` | string | SHA-256 digest specified below, as 64 lowercase hexadecimal characters |
| `signature` | string | Ed25519 signature specified below, as 128 lowercase hexadecimal characters |

All strings must contain Unicode scalar values; unpaired UTF-16 surrogate code
points are forbidden. `top_shap` can contain null, booleans, strings, arrays,
objects with string keys, signed 64-bit integers, and finite binary64 values.
NaN and positive/negative infinity are forbidden.

## Canonical JSON bytes

The normative serialization is equivalent to Python 3.11 or newer:

```python
json.dumps(
    value,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
).encode("utf-8")
```

Consequently:

1. Object keys are sorted lexicographically by Unicode code point.
2. There is no whitespace between tokens: commas and colons are exactly `,` and
   `:`.
3. Strings use JSON double quotes. Quote, reverse solidus, and control characters
   are escaped exactly as Python's `json.dumps`; non-ASCII scalar values are
   emitted directly and the result is encoded as UTF-8.
4. `true`, `false`, and `null` are lowercase.
5. Integers are base-10 with no leading zero. Binary64 values use CPython's
   shortest round-trippable decimal representation (including `.0` when emitted
   by CPython, lowercase `e`, and CPython's exponent sign/zero padding). A Rust
   implementation must reproduce this rendering rather than assuming every JSON
   library formats floats identically.

For the unsigned object described below, the resulting top-level key order is:

```text
class, confidence, features_hash, model_config_hash, model_id, node_id,
prev_hash, raw_csi_hash, seq, top_shap, ts_utc
```

For the complete stored object, the top-level key order is:

```text
class, confidence, features_hash, model_config_hash, model_id, node_id,
prev_hash, raw_csi_hash, record_hash, seq, signature, top_shap, ts_utc
```

## Hashing and signing procedure

For each event, perform these steps in order:

1. Set `seq` to zero for the first record; otherwise set it to the previous
   record's `seq + 1`.
2. Set genesis `prev_hash` to exactly 64 ASCII zero characters. Otherwise set it
   to the previous record's 64-character lowercase `record_hash`.
3. Construct the **unsigned object** from exactly the eleven fields `seq`,
   `ts_utc`, `node_id`, `raw_csi_hash`, `features_hash`, `model_id`,
   `model_config_hash`, `class`, `confidence`, `top_shap`, and `prev_hash`.
   Neither `record_hash` nor `signature` is present.
4. Canonically serialize the unsigned object. Call the resulting UTF-8 byte
   sequence `record_bytes`.
5. Compute `SHA-256(record_bytes)` and encode its 32 bytes as lowercase hex. This
   is `record_hash`.
6. Compute an Ed25519 signature over exactly `record_bytes`, using the logger's
   private key. Encode the 64 signature bytes as lowercase hex. This is
   `signature`. The digest hex is not signed separately; both digest and
   signature cover identical `record_bytes`.
7. Add `record_hash` and `signature`, canonically serialize the complete record,
   and append those bytes followed by exactly one LF byte (`0x0a`) to the store.
   LF is not part of `record_bytes` and is not hashed or signed. CRLF, blank
   lines, a missing final LF, a UTF-8 BOM, and non-canonical stored JSON are
   invalid.

### Minimal genesis shape

The exact `record_bytes` depend on event values, but every genesis unsigned
object includes:

```json
"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","seq":0
```

in the canonical positions shown above.

## Verification algorithm

A verifier starts with `expected_seq = 0` and `expected_prev_hash = "0" * 64`,
then processes physical lines from the beginning:

1. Require an LF-terminated, non-empty line. Remove only that final LF.
2. Decode strict UTF-8 and parse one JSON object. Require the exact schema and
   value constraints above.
3. Canonically serialize the complete parsed object and require byte-for-byte
   equality with the stored line. This detects otherwise-ignorable whitespace,
   escape, key-order, or duplicate-key alterations.
4. Require `seq == expected_seq` and `prev_hash == expected_prev_hash`.
5. Remove `record_hash` and `signature`, canonically serialize the remaining
   object, SHA-256 it, and require lowercase digest equality with `record_hash`.
6. Decode `signature` from lowercase hex and verify Ed25519 over those same
   canonical unsigned bytes using the known, out-of-band public key.
7. Set `expected_seq += 1` and `expected_prev_hash = record_hash`.

The chain is valid only if every step succeeds for every line. An empty existing
file is structurally valid but has no chain tip and cannot be timestamp-anchored.
Signature verification authenticates records to the holder of the private key;
OpenTimestamps anchoring separately establishes that a selected tip existed no
later than an independently verifiable time.

## Interoperability test vector

This genesis vector uses an Ed25519 test key. Its raw 32-byte public key is:

```text
03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
```

The exact UTF-8 `record_bytes` (shown as text, with no trailing LF) are:

```json
{"class":"normal","confidence":0.875,"features_hash":"2222222222222222222222222222222222222222222222222222222222222222","model_config_hash":"3333333333333333333333333333333333333333333333333333333333333333","model_id":"model-v1","node_id":"node-01","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","raw_csi_hash":"1111111111111111111111111111111111111111111111111111111111111111","seq":0,"top_shap":[],"ts_utc":"2026-07-13T12:00:00Z"}
```

Expected lowercase SHA-256:

```text
ef5d7fe2153bd2653b9e8b2d19044498dfe07016a479a2c831d7e63c774777e8
```

Expected lowercase Ed25519 signature:

```text
872e9ac9e8f2c0fb3473ecfc85d852a622460ae3a9718a35376f21eaa16c547b6a35fb9633b8501b982cb7ab535631ad50ab9b7b58ed3d873a896b059318650f
```

The exact stored line is the following bytes plus one final `0x0a`:

```json
{"class":"normal","confidence":0.875,"features_hash":"2222222222222222222222222222222222222222222222222222222222222222","model_config_hash":"3333333333333333333333333333333333333333333333333333333333333333","model_id":"model-v1","node_id":"node-01","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","raw_csi_hash":"1111111111111111111111111111111111111111111111111111111111111111","record_hash":"ef5d7fe2153bd2653b9e8b2d19044498dfe07016a479a2c831d7e63c774777e8","seq":0,"signature":"872e9ac9e8f2c0fb3473ecfc85d852a622460ae3a9718a35376f21eaa16c547b6a35fb9633b8501b982cb7ab535631ad50ab9b7b58ed3d873a896b059318650f","top_shap":[],"ts_utc":"2026-07-13T12:00:00Z"}
```
