"""Temporary boundary to the separately developed forensic event logger."""

from __future__ import annotations

from .models import CSIEvent


def log_event(event: CSIEvent) -> None:
    """Hand an authenticated raw event to the forensic logging subsystem.

    Integration contract for ``forensics/`` (must retain this exact signature):

        def log_event(event: sentrix_collector.models.CSIEvent) -> None

    The eventual implementation must raise an exception when durable handoff fails.
    It owns hash chaining and external timestamp anchoring. The collector must never
    sign or claim to verify ``timestamp_utc`` itself.
    """
    # TODO(forensics integration): replace this no-op with the separately built
    # hash-chain logger. Hashing/signing deliberately does not belong here.
    del event
