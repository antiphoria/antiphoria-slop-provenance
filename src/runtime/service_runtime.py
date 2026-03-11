"""Runtime helpers for long-lived Kafka-backed worker services."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from src.adapters.kafka_event_bus import KafkaEventBus
from src.env_config import read_env_int, read_env_optional
from src.repository import SQLiteRepository

# Resolve .env relative to project root so workers get consistent config regardless of CWD.
_ENV_PATH = Path(__file__).resolve().parents[2] / ".env"


def configure_logging() -> None:
    """Configure structured-ish log formatting for worker processes."""

    logging.basicConfig(
        level=read_env_optional("LOG_LEVEL", env_path=_ENV_PATH) or "INFO",
        format=("%(asctime)s %(levelname)s %(name)s " "message=%(message)s"),
    )


def build_repository() -> SQLiteRepository:
    """Build SQLite repository honoring optional shared STATE_DB_PATH."""

    state_db_path = read_env_optional("STATE_DB_PATH", env_path=_ENV_PATH)
    if state_db_path is None:
        return SQLiteRepository()
    return SQLiteRepository(db_path=Path(state_db_path).resolve())


def build_kafka_bus(service_name: str) -> KafkaEventBus:
    """Build and configure Kafka event bus for one service group."""

    bootstrap_servers = (
        read_env_optional("KAFKA_BOOTSTRAP_SERVERS", env_path=_ENV_PATH)
        or "localhost:9092"
    )
    metrics_dir = Path(
        read_env_optional("KAFKA_METRICS_DIR", env_path=_ENV_PATH) or ".metrics"
    ).resolve()
    metrics_snapshot_path = metrics_dir / f"{service_name}.json"
    dedup_repository = build_repository()
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


async def run_until_cancelled() -> None:
    """Keep service alive while event consumers run in background."""

    while True:
        await asyncio.sleep(1.0)
