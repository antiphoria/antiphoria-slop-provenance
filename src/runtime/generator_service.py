"""Kafka worker entrypoint for generation adapter."""

from __future__ import annotations

import asyncio
import os

from src.adapters.gemini_engine import GeminiEngineAdapter
from src.runtime.service_runtime import (
    build_kafka_bus,
    configure_logging,
    run_until_cancelled,
)


async def _run() -> None:
    configure_logging()
    bus = build_kafka_bus("generator-service")
    await bus.start()
    adapter = GeminiEngineAdapter(
        event_bus=bus,
        model_id=os.getenv("GENERATOR_MODEL_ID", "gemini-2.5-flash"),
    )
    await adapter.start()
    await run_until_cancelled()


def main() -> int:
    """Run generator worker process."""

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
