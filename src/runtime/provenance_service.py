"""Backward-compatible import shim for provenance worker entrypoint."""

from __future__ import annotations

from src.kafka.workers.provenance import main


if __name__ == "__main__":
    raise SystemExit(main())
