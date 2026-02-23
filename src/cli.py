"""Command-line entry point for the Slop Orchestrator.

This module composes the event bus and adapters, exposes a simple argparse UX,
and executes the asynchronous generation->notarization->ledger pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

import pygit2

from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.adapters.gemini_engine import GeminiEngineAdapter
from src.adapters.git_ledger import GitLedgerAdapter
from src.events import (
    EventBus,
    EventHandlerError,
    StoryCommitted,
    StoryRequested,
    StorySigned,
)
from src.repository import SQLiteRepository


class OrchestratorLock:
    """Exclusive lock to prevent concurrent orchestrator processes."""

    def __init__(self, lock_path: Path) -> None:
        """Initialize lock helper.

        Args:
            lock_path: Filesystem path to the lock file.
        """

        self._lock_path = lock_path
        self._fd: int | None = None

    def __enter__(self) -> "OrchestratorLock":
        """Acquire lock via atomic file creation.

        Raises:
            RuntimeError: If another orchestrator instance is already running.
        """

        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._fd = os.open(
                str(self._lock_path),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            )
        except FileExistsError as exc:
            raise RuntimeError(
                "Another orchestrator instance is already running "
                f"(lock: '{self._lock_path}')."
            ) from exc

        assert self._fd is not None
        os.write(self._fd, str(os.getpid()).encode("ascii"))
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Release lock file on process exit."""

        if self._fd is not None:
            os.close(self._fd)
        try:
            self._lock_path.unlink()
        except FileNotFoundError:
            pass


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Returns:
        Configured argparse parser for slop orchestration commands.
    """

    parser = argparse.ArgumentParser(
        prog="slop-cli",
        description="Event-driven slop generation and notarization pipeline.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate, notarize, and commit a new artifact.",
    )
    generate_parser.add_argument(
        "--prompt",
        required=True,
        help="Prompt text for story generation.",
    )
    generate_parser.add_argument(
        "--repo-path",
        default=".",
        help="Path to local git ledger repository (default: current directory).",
    )
    generate_parser.add_argument(
        "--model-id",
        default="gemini-2.5-flash",
        help="Google AI Studio model identifier.",
    )

    return parser


def _verify_git_commit(repository_path: Path, commit_oid: str) -> str:
    """Verify that the git ledger contains a specific commit OID.

    Args:
        repository_path: Path to local git repository.
        commit_oid: Commit object id to verify.

    Returns:
        Verified commit object id as string.

    Raises:
        RuntimeError: If repository is invalid or commit cannot be found.
    """

    try:
        repo = pygit2.Repository(str(repository_path.resolve()))
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(
            f"Unable to open git repository for verification: '{repository_path}'."
        ) from exc

    if repo.head_is_unborn:
        raise RuntimeError("Git repository contains no commits to verify.")

    try:
        commit = repo.revparse_single(commit_oid)
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(f"Commit verification failed for oid={commit_oid}.") from exc

    return str(commit.id)


async def _run_generate_command(args: argparse.Namespace) -> int:
    """Run the full async pipeline for the `generate` command.

    Args:
        args: Parsed command arguments.

    Returns:
        Process exit code (`0` on success).
    """

    event_bus = EventBus()
    repository = SQLiteRepository()
    repository_path = Path(args.repo_path)
    completion_future: asyncio.Future[StoryCommitted] = asyncio.get_running_loop().create_future()

    gemini_adapter = GeminiEngineAdapter(
        event_bus=event_bus,
        model_id=args.model_id,
    )
    notary_adapter = CryptoNotaryAdapter(event_bus=event_bus)
    ledger_adapter = GitLedgerAdapter(
        event_bus=event_bus,
        repository_path=repository_path,
    )

    async def _record_signed(event: StorySigned) -> None:
        """Persist signed lifecycle state in SQLite."""

        await asyncio.to_thread(
            repository.create_artifact_record,
            event.request_id,
            "signed",
            event.artifact,
            event.body,
            event.artifact.provenance.model_id,
        )

    async def _record_committed(event: StoryCommitted) -> None:
        """Persist committed lifecycle state and signal completion."""

        try:
            commit_id = await asyncio.to_thread(
                _verify_git_commit,
                repository_path,
                event.commit_oid,
            )
            await asyncio.to_thread(
                repository.update_artifact_status,
                event.request_id,
                "committed",
                event.ledger_path,
                commit_id,
            )
            if not completion_future.done():
                completion_future.set_result(event)
        except Exception as exc:
            if not completion_future.done():
                completion_future.set_exception(exc)
            raise

    async def _record_dispatch_error(event: EventHandlerError) -> None:
        """Fail pipeline fast when any async handler raises."""

        if completion_future.done():
            return
        completion_future.set_exception(
            RuntimeError(
                "Event handler failed: "
                f"event={event.event_type} "
                f"handler={event.handler_name} "
                f"type={event.error_type} "
                f"message={event.error_message}"
            )
        )

    await event_bus.subscribe(StorySigned, _record_signed)
    await event_bus.subscribe(StoryCommitted, _record_committed)
    await event_bus.subscribe_errors(_record_dispatch_error)

    await gemini_adapter.start()
    await notary_adapter.start()
    await ledger_adapter.start()

    request_event = StoryRequested(prompt=args.prompt)
    await event_bus.emit(request_event)
    committed_event = await asyncio.wait_for(completion_future, timeout=300.0)
    print(
        "Pipeline completed:",
        f"request_id={request_event.request_id}",
        f"commit={committed_event.commit_oid}",
        f"path={committed_event.ledger_path}",
    )
    return 0


async def _dispatch(args: argparse.Namespace) -> int:
    """Dispatch parsed CLI args to command handlers."""

    if args.command == "generate":
        return await _run_generate_command(args)
    raise RuntimeError(f"Unsupported command: {args.command}")


def main() -> int:
    """Parse arguments and run the asynchronous CLI dispatcher."""

    parser = build_parser()
    parsed_args = parser.parse_args()
    lock_base = Path.cwd()
    if getattr(parsed_args, "command", None) == "generate":
        lock_base = Path(parsed_args.repo_path).resolve()
    lock_path = lock_base / ".slop-orchestrator.lock"
    with OrchestratorLock(lock_path):
        return asyncio.run(_dispatch(parsed_args))


if __name__ == "__main__":
    raise SystemExit(main())
