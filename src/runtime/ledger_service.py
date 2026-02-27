"""Kafka worker entrypoint for git ledger adapter."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from src.adapters.git_ledger import GitLedgerAdapter
from src.runtime.service_runtime import build_kafka_bus, configure_logging, run_until_cancelled


async def _run() -> None:
    configure_logging()
    bus = build_kafka_bus("ledger-service")
    await bus.start()
    repository_path = Path(os.getenv("LEDGER_REPO_PATH", ".")).resolve()
    adapter = GitLedgerAdapter(event_bus=bus, repository_path=repository_path)
    await adapter.start()
    await run_until_cancelled()


def main() -> int:
    """Run ledger worker process."""

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
