from __future__ import annotations

import json
import os
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from forensics._format import (
    GENESIS_PREV_HASH,
    canonical_json_bytes,
    hash_unsigned_record,
)
from forensics.anchor import anchor_chain_tip
from forensics.chain_check import ChainVerificationError, verify_chain
from forensics.keys import (
    generate_and_save_keypair,
    generate_signing_key,
    load_private_key,
    load_public_key,
)
from forensics.logger import log_event

EventFactory = Callable[[int], dict[str, Any]]


def _configure_store(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv("SENTRIX_FORENSICS_STORE", str(path))


def _process_writer(store_path: str, key_path: str, writer_id: int, count: int) -> None:
    os.environ["SENTRIX_FORENSICS_STORE"] = store_path
    signer = load_private_key(key_path)
    for offset in range(count):
        unique = writer_id * 1_000 + offset
        digest = f"{unique:064x}"
        log_event(
            {
                "ts_utc": f"2026-07-13T13:00:{offset % 60:02d}Z",
                "node_id": f"writer-{writer_id}",
                "raw_csi_hash": digest,
                "features_hash": digest,
                "model_id": "concurrency-test",
                "model_config_hash": "a" * 64,
                "class": "normal",
                "confidence": 0.9,
                "top_shap": [],
            },
            signer,
        )


def test_interoperability_vector_matches_specification() -> None:
    unsigned = {
        "seq": 0,
        "ts_utc": "2026-07-13T12:00:00Z",
        "node_id": "node-01",
        "raw_csi_hash": "1" * 64,
        "features_hash": "2" * 64,
        "model_id": "model-v1",
        "model_config_hash": "3" * 64,
        "class": "normal",
        "confidence": 0.875,
        "top_shap": [],
        "prev_hash": "0" * 64,
    }
    expected_hash = "ef5d7fe2153bd2653b9e8b2d19044498dfe07016a479a2c831d7e63c774777e8"
    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(
            "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
        )
    )
    signature = bytes.fromhex(
        "872e9ac9e8f2c0fb3473ecfc85d852a622460ae3a9718a35376f21eaa16c547b"
        "6a35fb9633b8501b982cb7ab535631ad50ab9b7b58ed3d873a896b059318650f"
    )

    record_bytes, record_hash = hash_unsigned_record(unsigned)

    assert record_hash == expected_hash
    assert record_bytes.startswith(b'{"class":"normal","confidence":0.875,')
    assert record_bytes.endswith(b'"ts_utc":"2026-07-13T12:00:00Z"}')
    public_key.verify(signature, record_bytes)


def test_valid_chain_passes_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    _configure_store(monkeypatch, store)
    signer = generate_signing_key()

    records = [log_event(event_factory(index), signer) for index in range(4)]
    result = verify_chain(store, signer.public_key())

    assert result.records_verified == 4
    assert result.tip_hash == records[-1]["record_hash"]


def test_every_single_byte_flip_in_historical_record_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    _configure_store(monkeypatch, store)
    signer = generate_signing_key()
    for index in range(2):
        log_event(event_factory(index), signer)
    original = store.read_bytes()

    for position in range(len(original)):
        tampered = bytearray(original)
        tampered[position] ^= 1
        store.write_bytes(tampered)
        with pytest.raises(ChainVerificationError):
            verify_chain(store, signer.public_key())

    store.write_bytes(original)
    assert verify_chain(store, signer.public_key()).records_verified == 2


def test_valid_hash_with_invalid_signature_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    _configure_store(monkeypatch, store)
    signer = generate_signing_key()
    log_event(event_factory(1), signer)

    record = json.loads(store.read_bytes())
    record["class"] = "tampered-but-rehashed"
    _, record["record_hash"] = hash_unsigned_record(record)
    store.write_bytes(canonical_json_bytes(record) + b"\n")

    with pytest.raises(ChainVerificationError, match="signature"):
        verify_chain(store, signer.public_key())


def test_genesis_record_uses_documented_sentinel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    _configure_store(monkeypatch, store)
    signer = generate_signing_key()

    genesis = log_event(event_factory(0), signer)

    assert genesis["seq"] == 0
    assert genesis["prev_hash"] == GENESIS_PREV_HASH == "0" * 64
    assert verify_chain(store, signer.public_key()).records_verified == 1


def test_concurrent_process_writers_do_not_lose_or_corrupt_records(
    tmp_path: Path,
) -> None:
    store = tmp_path / "chain.jsonl"
    private_path = tmp_path / "logger.pem"
    public_path = tmp_path / "logger.pub.pem"
    generate_and_save_keypair(private_path, public_path)
    writers = 2
    per_writer = 12

    with ProcessPoolExecutor(max_workers=writers) as pool:
        futures = [
            pool.submit(
                _process_writer,
                str(store),
                str(private_path),
                writer_id,
                per_writer,
            )
            for writer_id in range(writers)
        ]
        for future in futures:
            future.result(timeout=30)

    result = verify_chain(store, load_public_key(public_path))
    lines = store.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    assert result.records_verified == writers * per_writer
    assert [record["seq"] for record in records] == list(range(writers * per_writer))
    assert len({record["raw_csi_hash"] for record in records}) == writers * per_writer


def test_key_helpers_round_trip_without_overwriting(tmp_path: Path) -> None:
    private_path = tmp_path / "keys" / "logger.pem"
    public_path = tmp_path / "keys" / "logger.pub.pem"
    generate_and_save_keypair(private_path, public_path, b"test-password")

    private_key = load_private_key(private_path, b"test-password")
    public_key = load_public_key(public_path)
    message = b"public verification test"
    public_key.verify(private_key.sign(message), message)

    with pytest.raises(FileExistsError):
        generate_and_save_keypair(private_path, public_path)


class _FakeTimestampBackend:
    def stamp(self, digest: bytes) -> bytes:
        assert len(digest) == 32
        return b"fake-ots-proof:" + digest


def test_anchor_interface_snapshots_tip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_factory: EventFactory,
) -> None:
    store = tmp_path / "chain.jsonl"
    proof = tmp_path / "anchors" / "tip.ots"
    _configure_store(monkeypatch, store)
    signer = Ed25519PrivateKey.generate()
    record = log_event(event_factory(0), signer)

    receipt = anchor_chain_tip(store, proof, _FakeTimestampBackend())

    assert receipt.sequence == 0
    assert receipt.tip_hash == record["record_hash"]
    assert proof.read_bytes().endswith(bytes.fromhex(record["record_hash"]))
