"""Kafka-specific runtime helpers (build_kafka_bus)."""

from __future__ import annotations

from pathlib import Path

from src.env_config import (
    read_env_int,
    read_env_optional,
    resolve_state_db_path,
)
from src.kafka.event_bus import KafkaEventBus
from src.repository import DedupRepository

_ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
_PROJECT_ROOT = _ENV_PATH.parent


def _sanitize_service_name(name: str) -> str:
    """Remove path components from service name."""
    return name.replace("..", "").replace("/", "-").replace("\\", "-") or "unknown"


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
    state_db_path = resolve_state_db_path(
        env_path=_ENV_PATH,
        project_root=_PROJECT_ROOT,
        service_name=safe_name,
    )
    if state_db_path is None:
        state_db_path = (
            _PROJECT_ROOT / ".orchestrator-state" / "dedup" / f"{safe_name}.db"
        ).resolve()
    state_db_path.parent.mkdir(parents=True, exist_ok=True)
    dedup_repository = DedupRepository(db_path=state_db_path)
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
