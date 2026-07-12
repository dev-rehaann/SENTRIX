"""Independent-facing verification API for a Sentrix forensic chain."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from filelock import FileLock

from ._store import StoreError, iter_validated_records
from .logger import LOCK_TIMEOUT_SECONDS, lock_path_for


class ChainVerificationError(ValueError):
    """A chain failed format, hash-link, or signature verification."""

    def __init__(self, line_number: int, reason: str) -> None:
        self.line_number = line_number
        self.reason = reason
        super().__init__(f"line {line_number}: {reason}")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Summary returned only after every available record passes verification."""

    records_verified: int
    tip_hash: str | None


def verify_chain(
    store_path: str | Path,
    public_key: Ed25519PublicKey,
) -> VerificationResult:
    """Verify canonical encoding, sequence, hashes, links, and Ed25519 signatures."""
    path = Path(store_path).expanduser().resolve()
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519PublicKey")
    if not path.exists():
        raise FileNotFoundError(path)

    records_verified = 0
    tip_hash: str | None = None
    lock = FileLock(str(lock_path_for(path)), timeout=LOCK_TIMEOUT_SECONDS)
    with lock:
        try:
            for line_number, record, signed_bytes in iter_validated_records(path):
                try:
                    public_key.verify(bytes.fromhex(record["signature"]), signed_bytes)
                except InvalidSignature as exc:
                    raise ChainVerificationError(
                        line_number,
                        "Ed25519 signature verification failed",
                    ) from exc
                records_verified += 1
                tip_hash = record["record_hash"]
        except StoreError as exc:
            raise ChainVerificationError(exc.line_number, exc.reason) from exc

    return VerificationResult(records_verified=records_verified, tip_hash=tip_hash)
