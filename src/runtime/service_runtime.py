"""Runtime helpers for worker-style long-running services."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from src.env_config import (
    read_env_optional,
    resolve_state_db_path,
)
from src.logging_config import get_log_context
from src.repository.dedup import DedupRepository
from src.repository.sqlite import SQLiteRepository
from src.runtime.cli_composition import (
    build_repository as build_cli_repository,
)

# Resolve .env relative to project root so workers get consistent
# config regardless of CWD.
_ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
_PROJECT_ROOT = _ENV_PATH.parent
_runtime_logger = logging.getLogger(__name__)


def _sanitize_service_name(name: str) -> str:
    """Remove path components from service name."""

    sanitized = name.replace("..", "").replace("/", "-").replace("\\", "-")
    return sanitized or "unknown"


def configure_logging() -> None:
    """Configure structured-ish log formatting for worker processes.

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


def build_repository() -> SQLiteRepository:
    """Build SQLite repository for shared artifact lifecycle (cache)."""
    return build_cli_repository(env_path=_ENV_PATH)


def build_dedup_repository(service_name: str) -> DedupRepository:
    """Build per-service dedup repository.

    Uses STATE_DB_PATH or ORCHESTRATOR_STATE_DIR.
    """

    state_db_path = resolve_state_db_path(
        env_path=_ENV_PATH,
        project_root=_PROJECT_ROOT,
        service_name=_sanitize_service_name(service_name),
    )
    if state_db_path is None:
        safe_name = _sanitize_service_name(service_name)
        state_db_path = (
            _PROJECT_ROOT / ".orchestrator-state" / "dedup" / f"{safe_name}.db"
        ).resolve()
    state_db_path.parent.mkdir(parents=True, exist_ok=True)
    return DedupRepository(db_path=state_db_path)


def _resolve_health_file_path(service_name: str) -> Path | None:
    """Resolve health file path from env or state directory."""

    health_file = read_env_optional("WORKER_HEALTH_FILE", env_path=_ENV_PATH)
    if health_file:
        return Path(health_file).resolve()
    state_db = read_env_optional("STATE_DB_PATH", env_path=_ENV_PATH)
    if state_db:
        base = Path(state_db).resolve().parent
    else:
        state_dir = read_env_optional(
            "ORCHESTRATOR_STATE_DIR",
            env_path=_ENV_PATH,
        )
        if not state_dir:
            return None
        base = Path(state_dir).resolve()
    safe_name = _sanitize_service_name(service_name).replace(".", "-")
    return base / "health" / f"{safe_name}.ok"


async def _health_writer_loop(
    health_path: Path,
    interval_sec: float = 30.0,
) -> None:
    """Write current timestamp to health file every interval_sec."""

    health_path.parent.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            import time

            health_path.write_text(str(int(time.time())), encoding="utf-8")
        except OSError:
            _runtime_logger.debug("Health file write failed", exc_info=True)
        await asyncio.sleep(interval_sec)


def start_health_writer(service_name: str) -> asyncio.Task[None] | None:
    """Start background task that writes health timestamp every 30s.

    Returns the task when WORKER_HEALTH_FILE or STATE_DB_PATH is set,
    else None.
    """

    health_path = _resolve_health_file_path(service_name)
    if health_path is None:
        return None
    return asyncio.create_task(_health_writer_loop(health_path))


async def run_until_cancelled(service_name: str = "worker") -> None:
    """Keep service alive while event consumers run in background.

    When health file path is configured, starts a background health writer.
    """

    _ = start_health_writer(service_name)
    while True:
        await asyncio.sleep(1.0)
