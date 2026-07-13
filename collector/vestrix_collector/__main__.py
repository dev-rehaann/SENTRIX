"""Command-line entry point for the collector."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence
from pathlib import Path

from .config import load_config
from .logging import configure_logging
from .server import CollectorServer


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Vestrix CSI collector")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/collector.yaml"),
        help="collector YAML config path (default: config/collector.yaml)",
    )
    return parser.parse_args(argv)


async def _run(config_path: Path) -> None:
    server = CollectorServer(load_config(config_path))
    await server.start()
    try:
        await asyncio.Event().wait()
    finally:
        await server.close()


def main(argv: Sequence[str] | None = None) -> None:
    """Run the collector until interrupted."""
    args = _parse_args(argv)
    configure_logging()
    try:
        asyncio.run(_run(args.config))
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
