"""Kafka worker entrypoint for provenance anchoring/timestamping."""

from __future__ import annotations

import asyncio
from pathlib import Path

from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.provenance_worker import ProvenanceWorkerAdapter
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter
from src.adapters.transparency_log import TransparencyLogAdapter
from src.env_config import read_env_optional
from src.runtime.service_runtime import (
    build_kafka_bus,
    build_repository,
    configure_logging,
    run_until_cancelled,
)
from src.services.provenance_service import ProvenanceService


def _resolve_tsa_ca_cert_path() -> Path | None:
    """Resolve optional TSA CA certificate path from env configuration."""

    raw_path = read_env_optional("RFC3161_CA_CERT_PATH")
    if raw_path is None:
        return None
    return Path(raw_path).resolve()


def _build_tsa_adapter() -> RFC3161TSAAdapter | None:
    """Build optional RFC3161 TSA adapter from env configuration."""

    tsa_url = read_env_optional("RFC3161_TSA_URL")
    if tsa_url is None:
        return None

    openssl_bin = read_env_optional("OPENSSL_BIN") or "openssl"
    openssl_conf = read_env_optional("OPENSSL_CONF")
    untrusted_path = read_env_optional("RFC3161_TSA_UNTRUSTED_CERT_PATH")

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


async def _run() -> None:
    configure_logging()
    bus = build_kafka_bus("provenance-service")
    await bus.start()

    repository = build_repository()
    key_registry = KeyRegistryAdapter(repository=repository)
    ledger_repo_path = Path(
        read_env_optional("LEDGER_REPO_PATH") or "."
    ).resolve()
    transparency_log_path = (
        ledger_repo_path / ".provenance" / "transparency-log.jsonl"
    )
    transparency_log_adapter = TransparencyLogAdapter(
        log_path=transparency_log_path,
        publish_url=read_env_optional("TRANSPARENCY_LOG_PUBLISH_URL"),
    )

    provenance_service = ProvenanceService(
        repository=repository,
        transparency_log_adapter=transparency_log_adapter,
        tsa_adapter=_build_tsa_adapter(),
        key_registry=key_registry,
    )
    adapter = ProvenanceWorkerAdapter(
        event_bus=bus,
        provenance_service=provenance_service,
        repository_path=ledger_repo_path,
        tsa_ca_cert_path=_resolve_tsa_ca_cert_path(),
    )
    await adapter.start()
    await run_until_cancelled()


def main() -> int:
    """Run provenance worker process."""

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
