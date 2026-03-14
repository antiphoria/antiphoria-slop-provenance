"""Kafka worker entrypoint for provenance anchoring/timestamping."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.ots_adapter import OTSAdapter, build_ots_adapter
from src.adapters.ots_queue import OtsQueueAdapter
from src.adapters.provenance_worker import ProvenanceWorkerAdapter
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter
from src.adapters.transparency_log import (
    TransparencyLogAdapter,
    build_supabase_publish_config,
)
from src.env_config import read_env_int, read_env_optional
from src.kafka.runtime import build_kafka_bus
from src.runtime.service_runtime import (
    build_repository,
    configure_logging,
    run_until_cancelled,
)
from src.services.ots_upgrade import process_single_ots_record
from src.services.provenance_service import ProvenanceService

_logger = logging.getLogger(__name__)


def _resolve_env_path() -> Path:
    """Resolve .env path relative to project root (invariant to CWD)."""
    return Path(__file__).resolve().parents[3] / ".env"


def _resolve_tsa_ca_cert_path(env_path: Path) -> Path | None:
    """Resolve optional TSA CA certificate path from env configuration."""

    raw_path = read_env_optional("RFC3161_CA_CERT_PATH", env_path=env_path)
    if raw_path is None:
        return None
    return Path(raw_path).resolve()


def _build_tsa_adapter(env_path: Path) -> RFC3161TSAAdapter | None:
    """Build optional RFC3161 TSA adapter from env configuration."""

    tsa_url = read_env_optional("RFC3161_TSA_URL", env_path=env_path)
    if tsa_url is None:
        return None

    openssl_bin = read_env_optional("OPENSSL_BIN", env_path=env_path) or "openssl"
    openssl_conf = read_env_optional("OPENSSL_CONF", env_path=env_path)
    untrusted_path = read_env_optional(
        "RFC3161_TSA_UNTRUSTED_CERT_PATH", env_path=env_path
    )

    return RFC3161TSAAdapter(
        tsa_url=tsa_url,
        openssl_bin=openssl_bin,
        untrusted_cert_path=(
            None if untrusted_path is None else Path(untrusted_path).resolve()
        ),
        openssl_conf_path=(
            None if openssl_conf is None else Path(openssl_conf).resolve()
        ),
    )


async def _ots_furnace_loop(
    repository,
    ots_queue: OtsQueueAdapter,
    provenance_service: ProvenanceService,
    ots_adapter: OTSAdapter,
    transparency_log_adapter: TransparencyLogAdapter,
    bus,
    repository_path: Path,
    interval_sec: int,
    batch_size: int,
    max_concurrent: int,
) -> None:
    """Background loop: upgrade pending OTS proofs, atomic quench (Git -> append_entry -> OTS queue -> emit)."""

    ots_path_template = ".provenance/ots-{request_id}.ots"
    semaphore = asyncio.Semaphore(max_concurrent)
    while True:
        try:
            records = await asyncio.to_thread(
                ots_queue.get_pending_records, batch_size
            )
        except Exception as exc:
            _logger.exception("OTS furnace: get_pending failed: %s", exc)
            await asyncio.sleep(interval_sec)
            continue

        if records:
            tasks = [
                process_single_ots_record(
                    semaphore,
                    record,
                    repository,
                    ots_queue,
                    provenance_service,
                    ots_adapter,
                    transparency_log_adapter,
                    repository_path,
                    ots_path_template,
                    bus,
                )
                for record in records
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        await asyncio.sleep(interval_sec)


async def _run() -> None:
    configure_logging()
    bus = build_kafka_bus("provenance-service")
    await bus.start()

    env_path = _resolve_env_path()
    repository = build_repository()
    key_registry = KeyRegistryAdapter(repository=repository)
    ledger_repo_path = Path(
        read_env_optional("LEDGER_REPO_PATH", env_path=env_path) or "."
    ).resolve()
    transparency_log_path = (
        ledger_repo_path / ".provenance" / "transparency-log.jsonl"
    )
    publish_url = read_env_optional(
        "TRANSPARENCY_LOG_PUBLISH_URL", env_path=env_path
    )
    publish_headers, publish_supabase_format = build_supabase_publish_config(
        publish_url, env_path=env_path
    )
    transparency_log_adapter = TransparencyLogAdapter(
        log_path=transparency_log_path,
        publish_url=publish_url,
        publish_headers=publish_headers if publish_headers else None,
        publish_supabase_format=publish_supabase_format,
    )

    ots_adapter = build_ots_adapter(env_path)
    provenance_service = ProvenanceService(
        repository=repository,
        transparency_log_adapter=transparency_log_adapter,
        tsa_adapter=_build_tsa_adapter(env_path),
        key_registry=key_registry,
        ots_adapter=ots_adapter,
        env_path=env_path,
    )
    adapter = ProvenanceWorkerAdapter(
        event_bus=bus,
        provenance_service=provenance_service,
        repository_path=ledger_repo_path,
        tsa_ca_cert_path=_resolve_tsa_ca_cert_path(env_path),
        env_path=env_path,
    )
    await adapter.start()

    if ots_adapter is not None:
        ots_queue = OtsQueueAdapter(
            repository_path=ledger_repo_path,
            env_path=env_path,
        )
        interval_sec = read_env_int(
            "OTS_FURNACE_INTERVAL_SEC", default=3600, env_path=env_path
        )
        batch_size = read_env_int(
            "OTS_FURNACE_BATCH_SIZE", default=100, env_path=env_path
        )
        max_concurrent = read_env_int(
            "OTS_FURNACE_MAX_CONCURRENT", default=5, env_path=env_path
        )
        asyncio.create_task(
            _ots_furnace_loop(
                repository=repository,
                ots_queue=ots_queue,
                provenance_service=provenance_service,
                ots_adapter=ots_adapter,
                transparency_log_adapter=transparency_log_adapter,
                bus=bus,
                repository_path=ledger_repo_path,
                interval_sec=interval_sec,
                batch_size=batch_size,
                max_concurrent=max_concurrent,
            )
        )

    await run_until_cancelled("provenance-service")


def main() -> int:
    """Run provenance worker process."""

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
