"""Smoke test for Kafka-backed generate pipeline."""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from src.adapters.kafka_event_bus import KafkaEventBus
from src.events import StoryRequested
from src.runtime.bootstrap_topics import _bootstrap_topics


async def _run_smoke(
    prompt: str,
    bootstrap_servers: str,
    ledger_repo_path: Path,
    timeout_sec: float,
    bootstrap_topics: bool,
) -> int:
    """Emit one generation request and wait for artifact file creation."""

    if bootstrap_topics:
        await _bootstrap_topics(bootstrap_servers=bootstrap_servers, partitions=1)

    bus = KafkaEventBus(
        bootstrap_servers=bootstrap_servers,
        consumer_group="smoke-client",
    )
    await bus.start()
    try:
        event = StoryRequested(prompt=prompt)
        await bus.emit(event)
    finally:
        await bus.stop()

    artifact_path = ledger_repo_path / "artifacts" / f"{event.request_id}.md"
    deadline = asyncio.get_running_loop().time() + timeout_sec
    while asyncio.get_running_loop().time() < deadline:
        if artifact_path.exists():
            print(f"[OK] Smoke succeeded: {artifact_path}")
            return 0
        await asyncio.sleep(1.0)

    raise RuntimeError(
        "Smoke timeout waiting for artifact file. "
        f"expected='{artifact_path}' request_id={event.request_id}"
    )


def main() -> int:
    """CLI entrypoint for Kafka smoke validation."""

    parser = argparse.ArgumentParser(prog="slop-smoke-kafka")
    parser.add_argument(
        "--prompt",
        default="Smoke test brutalist story.",
        help="Prompt used for smoke generation.",
    )
    parser.add_argument(
        "--bootstrap-servers",
        default=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        help="Kafka bootstrap servers.",
    )
    parser.add_argument(
        "--ledger-repo-path",
        default=os.getenv("LEDGER_REPO_PATH", "./ledger"),
        help="Path to ledger git repository.",
    )
    parser.add_argument(
        "--timeout-sec",
        type=float,
        default=120.0,
        help="Maximum seconds to wait for artifact output.",
    )
    parser.add_argument(
        "--bootstrap-topics",
        action="store_true",
        help="Create required Kafka topics before dispatch.",
    )
    args = parser.parse_args()

    return asyncio.run(
        _run_smoke(
            prompt=args.prompt,
            bootstrap_servers=args.bootstrap_servers,
            ledger_repo_path=Path(args.ledger_repo_path).resolve(),
            timeout_sec=args.timeout_sec,
            bootstrap_topics=args.bootstrap_topics,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
