"""Kafka worker entrypoint for post-commit provenance processing."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.provenance_worker import ProvenanceWorkerAdapter
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter
from src.adapters.transparency_log import TransparencyLogAdapter
from src.repository import SQLiteRepository
from src.runtime.service_runtime import (
    build_kafka_bus,
    configure_logging,
    run_until_cancelled,
)
from src.services.provenance_service import ProvenanceService


async def _run() -> None:
    configure_logging()
    bus = build_kafka_bus("provenance-service")
    await bus.start()

    repository = SQLiteRepository()
    repository_path = Path(os.getenv("LEDGER_REPO_PATH", ".")).resolve()
    transparency_log_path = repository_path / ".provenance" / "transparency-log.jsonl"
    transparency = TransparencyLogAdapter(
        log_path=transparency_log_path,
        publish_url=os.getenv("TRANSPARENCY_LOG_PUBLISH_URL"),
    )
    tsa_url = os.getenv("RFC3161_TSA_URL")
    tsa = None if tsa_url is None else RFC3161TSAAdapter(tsa_url=tsa_url)
    service = ProvenanceService(
        repository=repository,
        transparency_log_adapter=transparency,
        tsa_adapter=tsa,
        key_registry=KeyRegistryAdapter(repository=repository),
    )
    tsa_ca_cert_raw = os.getenv("RFC3161_CA_CERT_PATH")
    tsa_ca_cert_path = (
        None if tsa_ca_cert_raw is None else Path(tsa_ca_cert_raw).resolve()
    )
    worker = ProvenanceWorkerAdapter(
        event_bus=bus,
        provenance_service=service,
        repository_path=repository_path,
        tsa_ca_cert_path=tsa_ca_cert_path,
    )
    await worker.start()
    await run_until_cancelled()


def main() -> int:
    """Run provenance worker process."""

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
