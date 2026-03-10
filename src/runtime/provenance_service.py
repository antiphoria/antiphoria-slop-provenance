"""Backward-compatible import shim for provenance worker entrypoint."""

from __future__ import annotations

from src.runtime.provenance_worker_service import main


if __name__ == "__main__":
    raise SystemExit(main())
