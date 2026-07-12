"""Interface for periodically anchoring a chain tip with OpenTimestamps."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from filelock import FileLock

from ._store import chain_tip
from .logger import LOCK_TIMEOUT_SECONDS, lock_path_for


class TimestampBackend(Protocol):
    """Backend boundary; only implementations of this method may use the network."""

    def stamp(self, digest: bytes) -> bytes:
        """Submit a 32-byte digest and return a serialized timestamp proof."""
        ...


@dataclass(frozen=True, slots=True)
class AnchorReceipt:
    """Metadata for a proof written for one immutable chain tip."""

    sequence: int
    tip_hash: str
    proof_path: Path


class OpenTimestampsBackend:
    """Placeholder for the Python OpenTimestamps client integration."""

    def stamp(self, digest: bytes) -> bytes:
        """Submit ``digest`` to OpenTimestamps calendars.

        TODO: pin a compatible ``opentimestamps-client`` release, construct a
        detached timestamp over this already-computed SHA-256 digest, submit it to
        explicitly configured calendars, and serialize the resulting ``.ots``
        proof. The package's public Python API is not stable/documented enough to
        make those byte-level and network-policy choices implicitly. Until then,
        deployments should inject a reviewed ``TimestampBackend`` implementation.
        """
        if len(digest) != 32:
            raise ValueError("OpenTimestamps input must be a 32-byte digest")
        raise NotImplementedError("OpenTimestamps client integration is not pinned")


def anchor_chain_tip(
    store_path: str | Path,
    proof_path: str | Path,
    backend: TimestampBackend,
) -> AnchorReceipt:
    """Snapshot the current tip, timestamp it, and durably save the returned proof."""
    store = Path(store_path).expanduser().resolve()
    target = Path(proof_path).expanduser().resolve()
    if not store.exists():
        raise FileNotFoundError(store)

    lock = FileLock(str(lock_path_for(store)), timeout=LOCK_TIMEOUT_SECONDS)
    with lock:
        next_seq, tip_hash = chain_tip(store)
    if next_seq == 0:
        raise ValueError("cannot anchor an empty chain")

    proof = backend.stamp(bytes.fromhex(tip_hash))
    if not isinstance(proof, bytes) or not proof:
        raise ValueError("timestamp backend returned an empty or non-bytes proof")

    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as proof_file:
        proof_file.write(proof)
        proof_file.flush()
        os.fsync(proof_file.fileno())
    return AnchorReceipt(sequence=next_seq - 1, tip_hash=tip_hash, proof_path=target)
