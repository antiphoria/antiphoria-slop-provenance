"""Runtime helpers for long-lived Kafka-backed worker services."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from src.adapters.kafka_event_bus import KafkaEventBus
from src.repository import SQLiteRepository


def configure_logging() -> None:
    """Configure structured-ish log formatting for worker processes."""

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format=(
            "%(asctime)s %(levelname)s %(name)s "
            "message=%(message)s"
        ),
    )


def build_kafka_bus(service_name: str) -> KafkaEventBus:
    """Build and configure Kafka event bus for one service group."""

    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    state_db_path = os.getenv("STATE_DB_PATH")
    metrics_dir = Path(os.getenv("KAFKA_METRICS_DIR", ".metrics")).resolve()
    metrics_snapshot_path = metrics_dir / f"{service_name}.json"
    dedup_repository = SQLiteRepository(
        db_path=None if state_db_path is None else Path(state_db_path).resolve()
    )
    return KafkaEventBus(
        bootstrap_servers=bootstrap_servers,
        consumer_group=service_name,
        max_retries=int(os.getenv("KAFKA_MAX_RETRIES", "3")),
        dedup_repository=dedup_repository,
        metrics_snapshot_path=metrics_snapshot_path,
        metrics_flush_every=int(os.getenv("KAFKA_METRICS_FLUSH_EVERY", "100")),
    )


async def run_until_cancelled() -> None:
    """Keep service alive while event consumers run in background."""

    while True:
        await asyncio.sleep(1.0)
