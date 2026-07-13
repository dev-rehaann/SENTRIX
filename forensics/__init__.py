"""Vestrix tamper-evident forensic event logging."""

from .chain_check import ChainVerificationError, VerificationResult, verify_chain
from .logger import log_event

__all__ = [
    "ChainVerificationError",
    "VerificationResult",
    "log_event",
    "verify_chain",
]
