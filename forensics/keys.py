"""Ed25519 signing-key generation and persistence helpers."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_signing_key() -> Ed25519PrivateKey:
    """Generate a new Ed25519 private key in memory."""
    return Ed25519PrivateKey.generate()


def save_private_key(
    private_key: Ed25519PrivateKey,
    path: str | Path,
    password: bytes | None = None,
) -> Path:
    """Save a private key as PKCS#8 PEM, refusing to overwrite an existing file."""
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    encryption: serialization.KeySerializationEncryption
    if password is None:
        encryption = serialization.NoEncryption()
    else:
        if not password:
            raise ValueError("password must not be empty")
        encryption = serialization.BestAvailableEncryption(password)
    encoded = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    _write_secret_exclusive(target, encoded)
    return target


def save_public_key(public_key: Ed25519PublicKey, path: str | Path) -> Path:
    """Save an Ed25519 public key as SubjectPublicKeyInfo PEM."""
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with target.open("xb") as key_file:
        key_file.write(encoded)
        key_file.flush()
        os.fsync(key_file.fileno())
    return target


def load_private_key(
    path: str | Path,
    password: bytes | None = None,
) -> Ed25519PrivateKey:
    """Load an Ed25519 private key without exposing its material."""
    loaded = serialization.load_pem_private_key(
        Path(path).expanduser().read_bytes(),
        password=password,
    )
    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError("key file does not contain an Ed25519 private key")
    return loaded


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from SubjectPublicKeyInfo PEM."""
    loaded = serialization.load_pem_public_key(Path(path).expanduser().read_bytes())
    if not isinstance(loaded, Ed25519PublicKey):
        raise TypeError("key file does not contain an Ed25519 public key")
    return loaded


def generate_and_save_keypair(
    private_key_path: str | Path,
    public_key_path: str | Path,
    password: bytes | None = None,
) -> tuple[Path, Path]:
    """Generate and save a node/logger keypair without printing secret material."""
    private_target = Path(private_key_path).expanduser().resolve()
    public_target = Path(public_key_path).expanduser().resolve()
    if private_target.exists() or public_target.exists():
        raise FileExistsError("refusing to overwrite an existing key file")
    key = generate_signing_key()
    save_private_key(key, private_target, password)
    try:
        save_public_key(key.public_key(), public_target)
    except Exception:
        private_target.unlink(missing_ok=True)
        raise
    return private_target, public_target


def _write_secret_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as key_file:
            descriptor = -1
            key_file.write(data)
            key_file.flush()
            os.fsync(key_file.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
