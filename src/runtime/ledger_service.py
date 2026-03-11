"""Kafka worker entrypoint for git ledger adapter."""

from __future__ import annotations

import asyncio
from pathlib import Path

from src.adapters.git_ledger import GitLedgerAdapter
from src.env_config import read_env_optional
from src.events import StoryCommitted
from src.runtime.service_runtime import (
    build_kafka_bus,
    build_repository,
    configure_logging,
    run_until_cancelled,
)

# Resolve .env relative to project root so config is consistent regardless of CWD.
_ENV_PATH = Path(__file__).resolve().parents[2] / ".env"


async def _run() -> None:
    configure_logging()
    bus = build_kafka_bus("ledger-service")
    await bus.start()
    repository = build_repository()

    async def _record_committed(event: StoryCommitted) -> None:
        existing = await asyncio.to_thread(
            repository.get_artifact_record,
            event.request_id,
        )
        if existing is None:
            # Notary persistence may have been unavailable or started late.
            return
        await asyncio.to_thread(
            repository.update_artifact_status,
            event.request_id,
            "committed",
            event.ledger_path,
            event.commit_oid,
        )

    await bus.subscribe(StoryCommitted, _record_committed)
    repository_path = Path(
        read_env_optional("LEDGER_REPO_PATH", env_path=_ENV_PATH) or "."
    ).resolve()
    adapter = GitLedgerAdapter(event_bus=bus, repository_path=repository_path)
    await adapter.start()
    await run_until_cancelled()


def main() -> int:
    """Run ledger worker process."""

    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
