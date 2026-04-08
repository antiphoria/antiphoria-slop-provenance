"""Runtime helpers shared by CLI and other entrypoints."""

from __future__ import annotations

import logging
from pathlib import Path

from src.env_config import read_env_optional
from src.logging_config import get_log_context

# Resolve .env relative to project root for consistent config regardless of CWD.
_ENV_PATH = Path(__file__).resolve().parents[2] / ".env"


def configure_logging() -> None:
    """Configure structured-ish log formatting.

    Supports request_id in log records for request-scoped correlation.
    Use extra={"request_id": "..."} when logging; defaults to '-' when absent.
    """

    class RequestIdFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            if not hasattr(record, "request_id"):
                ctx = get_log_context()
                record.request_id = ctx.request_id or "-"  # type: ignore[attr-defined]
            return super().format(record)

    formatter = RequestIdFormatter(
        "%(asctime)s %(levelname)s %(name)s request_id=%(request_id)s message=%(message)s"
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root = logging.getLogger()
    level_name = (
        read_env_optional(
            "LOG_LEVEL",
            env_path=_ENV_PATH,
        )
        or "INFO"
    )
    root.setLevel(getattr(logging, level_name.upper(), logging.INFO))
    root.handlers.clear()
    root.addHandler(handler)
