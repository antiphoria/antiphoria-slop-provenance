"""Runtime helpers for long-lived Kafka-backed worker services."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from src.adapters.kafka_event_bus import KafkaEventBus
from src.env_config import read_env_int, read_env_optional
from src.repository import DedupRepository, SQLiteRepository

# Resolve .env relative to project root so workers get consistent config regardless of CWD.
_ENV_PATH = Path(__file__).resolve().parents[2] / ".env"


def _sanitize_service_name(name: str) -> str:
    """Remove path components from service name."""
    return name.replace("..", "").replace("/", "-").replace("\\", "-") or "unknown"


def configure_logging() -> None:
    """Configure structured-ish log formatting for worker processes.

    Supports request_id in log records for request-scoped correlation.
    Use extra={"request_id": "..."} when logging; defaults to '-' when absent.
    """

    class RequestIdFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            if not hasattr(record, "request_id"):
                record.request_id = "-"  # type: ignore[attr-defined]
            return super().format(record)

    formatter = RequestIdFormatter(
        "%(asctime)s %(levelname)s %(name)s request_id=%(request_id)s message=%(message)s"
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root = logging.getLogger()
    level_name = read_env_optional("LOG_LEVEL", env_path=_ENV_PATH) or "INFO"
    root.setLevel(getattr(logging, level_name.upper(), logging.INFO))
    root.handlers.clear()
    root.addHandler(handler)


def build_repository() -> SQLiteRepository:
    """Build SQLite repository for shared artifact lifecycle (ARTIFACT_DB_PATH)."""

    artifact_db_path = read_env_optional("ARTIFACT_DB_PATH", env_path=_ENV_PATH)
    if artifact_db_path is None:
        return SQLiteRepository()
    return SQLiteRepository(db_path=Path(artifact_db_path).resolve())


def build_dedup_repository(service_name: str) -> DedupRepository:
    """Build per-service dedup repository (STATE_DB_PATH)."""

    state_db_path = read_env_optional("STATE_DB_PATH", env_path=_ENV_PATH)
    if state_db_path is None:
        safe_name = _sanitize_service_name(service_name)
        return DedupRepository(db_path=Path(f"state/{safe_name}.db"))
    return DedupRepository(db_path=Path(state_db_path).resolve())


def build_kafka_bus(service_name: str) -> KafkaEventBus:
    """Build and configure Kafka event bus for one service group."""

    bootstrap_servers = (
        read_env_optional("KAFKA_BOOTSTRAP_SERVERS", env_path=_ENV_PATH)
        or "localhost:9092"
    )
    metrics_dir = Path(
        read_env_optional("KAFKA_METRICS_DIR", env_path=_ENV_PATH) or ".metrics"
    ).resolve()
    safe_name = _sanitize_service_name(service_name)
    metrics_snapshot_path = metrics_dir / f"{safe_name}.json"
    dedup_repository = build_dedup_repository(service_name)
    return KafkaEventBus(
        bootstrap_servers=bootstrap_servers,
        consumer_group=service_name,
        max_retries=read_env_int("KAFKA_MAX_RETRIES", default=3, env_path=_ENV_PATH),
        dedup_repository=dedup_repository,
        metrics_snapshot_path=metrics_snapshot_path,
        metrics_flush_every=read_env_int(
            "KAFKA_METRICS_FLUSH_EVERY", default=100, env_path=_ENV_PATH
        ),
    )


def _resolve_health_file_path(service_name: str) -> Path | None:
    """Resolve health file path from KAFKA_HEALTH_FILE or derive from STATE_DB_PATH."""

    health_file = read_env_optional("KAFKA_HEALTH_FILE", env_path=_ENV_PATH)
    if health_file:
        return Path(health_file).resolve()
    state_db = read_env_optional("STATE_DB_PATH", env_path=_ENV_PATH)
    if state_db:
        state_dir = Path(state_db).resolve().parent
        safe_name = _sanitize_service_name(service_name).replace(".", "-")
        return state_dir / "health" / f"{safe_name}.ok"
    return None


async def _health_writer_loop(health_path: Path, interval_sec: float = 30.0) -> None:
    """Write current timestamp to health file every interval_sec."""

    health_path.parent.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            import time

            health_path.write_text(str(int(time.time())), encoding="utf-8")
        except Exception:
            pass
        await asyncio.sleep(interval_sec)


def start_health_writer(service_name: str) -> asyncio.Task[None] | None:
    """Start background task that writes health timestamp every 30s.

    Returns the task when KAFKA_HEALTH_FILE or STATE_DB_PATH is set, else None.
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
