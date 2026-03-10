"""Kafka worker entrypoint for provenance telemetry adapter."""

from __future__ import annotations

import asyncio

from src.adapters.provenance_telemetry import ProvenanceTelemetryAdapter
from src.runtime.service_runtime import (
    build_kafka_bus,
    build_repository,
    configure_logging,
    run_until_cancelled,
)


async def _run() -> None:
    configure_logging()
    bus = build_kafka_bus("telemetry-service")
    await bus.start()
    repository = build_repository()
    adapter = ProvenanceTelemetryAdapter(event_bus=bus, repository=repository)
    await adapter.start()
    await run_until_cancelled()


def main() -> int:
    """Run telemetry worker process."""

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
