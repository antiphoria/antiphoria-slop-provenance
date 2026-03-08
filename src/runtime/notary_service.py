"""Kafka worker entrypoint for notary adapter."""

from __future__ import annotations

import asyncio

from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.runtime.service_runtime import (
    build_kafka_bus,
    configure_logging,
    run_until_cancelled,
)


async def _run() -> None:
    configure_logging()
    bus = build_kafka_bus("notary-service")
    await bus.start()
    adapter = CryptoNotaryAdapter(event_bus=bus)
    await adapter.start()
    await run_until_cancelled()


def main() -> int:
    """Run notary worker process."""

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
