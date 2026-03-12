"""Smoke test for Kafka-backed generate pipeline."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from uuid import UUID

import pygit2

from src.adapters.kafka_event_bus import KafkaEventBus
from src.env_config import read_env_optional
from src.events import StoryRequested
from src.runtime.bootstrap_topics import _bootstrap_topics


def _resolve_artifact_branch_target(
    ledger_repo_path: Path,
    request_id: UUID,
) -> tuple[str, str, str] | None:
    """Return branch, commit, and path when artifact branch/blob exists."""

    try:
        repo = pygit2.Repository(str(ledger_repo_path))
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(f"Invalid ledger git repository: '{ledger_repo_path}'.") from exc

    branch_name = f"artifact/{request_id}"
    ref_name = f"refs/heads/{branch_name}"
    try:
        reference = repo.lookup_reference(ref_name)
    except KeyError:
        return None

    commit_obj = repo[reference.target]
    if not isinstance(commit_obj, pygit2.Commit):
        raise RuntimeError(f"Branch ref '{ref_name}' does not point to a commit.")

    artifact_path = f"{request_id}.md"
    try:
        tree_entry = commit_obj.tree[artifact_path]
    except KeyError:
        return None

    blob_obj = repo[tree_entry.id]
    if not isinstance(blob_obj, pygit2.Blob):
        raise RuntimeError(
            f"Artifact path '{artifact_path}' on '{branch_name}' is not a blob."
        )
    return branch_name, str(commit_obj.id), artifact_path


async def _run_smoke(
    prompt: str,
    bootstrap_servers: str,
    ledger_repo_path: Path,
    timeout_sec: float,
    bootstrap_topics: bool,
) -> int:
    """Emit one generation request and wait for artifact file creation."""

    if bootstrap_topics:
        await _bootstrap_topics(
            bootstrap_servers=bootstrap_servers,
            partitions=1,
        )

    bus = KafkaEventBus(
        bootstrap_servers=bootstrap_servers,
        consumer_group="smoke-client",
    )
    await bus.start()
    try:
        event = StoryRequested(prompt=prompt)
        await bus.emit(event)
        print(f"Emitted StoryRequested request_id={event.request_id}")
    finally:
        await bus.stop()

    expected_branch = f"artifact/{event.request_id}"
    expected_path = f"{event.request_id}.md"
    deadline = asyncio.get_running_loop().time() + timeout_sec
    poll_count = 0
    while asyncio.get_running_loop().time() < deadline:
        resolved_target = _resolve_artifact_branch_target(
            ledger_repo_path=ledger_repo_path,
            request_id=event.request_id,
        )
        if resolved_target is not None:
            branch_name, commit_oid, artifact_path = resolved_target
            print(
                "[OK] Smoke succeeded:",
                f"request_id={event.request_id}",
                f"branch={branch_name}",
                f"commit={commit_oid}",
                f"path={artifact_path}",
            )
            return 0
        poll_count += 1
        if poll_count % 10 == 0:
            elapsed = int(asyncio.get_running_loop().time() - (deadline - timeout_sec))
            print(
                f"Waiting for artifact (request_id={event.request_id}) "
                f"... {elapsed}s elapsed"
            )
        await asyncio.sleep(1.0)

    raise RuntimeError(
        "Smoke timeout waiting for branch artifact commit. "
        f"expected_branch='{expected_branch}' expected_path='{expected_path}' "
        f"request_id={event.request_id}"
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
        default=(
            read_env_optional("KAFKA_BOOTSTRAP_SERVERS")
            or "localhost:9092"
        ),
        help="Kafka bootstrap servers.",
    )
    parser.add_argument(
        "--ledger-repo-path",
        default=read_env_optional("LEDGER_REPO_PATH") or "./ledger",
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

    ledger_path = Path(args.ledger_repo_path)
    if not ledger_path.is_absolute():
        project_root = Path(__file__).resolve().parents[2]
        ledger_path = (project_root / ledger_path).resolve()

    return asyncio.run(
        _run_smoke(
            prompt=args.prompt,
            bootstrap_servers=args.bootstrap_servers,
            ledger_repo_path=ledger_path,
            timeout_sec=args.timeout_sec,
            bootstrap_topics=args.bootstrap_topics,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
