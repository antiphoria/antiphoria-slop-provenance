"""Append-only OTS queue stored in the Archive repo.

The queue lives at .provenance/ots-queue.jsonl on the default branch (e.g. main).
Each line is a JSON event: pending, forged, or failed.
Current state is derived by taking the latest event per request_id.

Uses read-modify-commit: content is read from git ref (source of truth), new line
appended in memory, full blob committed. Git history is preserved; branch tip is
replaced. FileLock coordinates within a single process; multiple writers require
distributed locking or a single-writer topology.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pygit2
from filelock import FileLock

from src.env_config import read_env_optional
from src.repository.types import OtsForgeRecord, OtsForgeStatus

_logger = logging.getLogger(__name__)

_QUEUE_RELATIVE_PATH = ".provenance/ots-queue.jsonl"
_DEFAULT_QUEUE_REF = "refs/heads/main"
_DEFAULT_LEDGER_AUTHOR_NAME = "Antiphoria Slop Provenance"
_DEFAULT_LEDGER_AUTHOR_EMAIL = "bot@antiphoria.local"
_QUEUE_GROWTH_WARN_EVERY_LINES = 10_000


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class OtsQueueAdapter:
    """Append-only OTS queue in the Archive repo with Git commit on each append."""

    def __init__(
        self,
        repository_path: Path,
        queue_ref: str | None = None,
        env_path: Path | None = None,
    ) -> None:
        self._repository_path = repository_path.resolve()
        self._queue_ref = (
            queue_ref or read_env_optional("OTS_QUEUE_REF", env_path=env_path) or _DEFAULT_QUEUE_REF
        )
        self._env_path = env_path
        self._queue_path = self._repository_path / _QUEUE_RELATIVE_PATH

    def _resolve_commit_signature(self, repo: pygit2.Repository) -> pygit2.Signature:
        name = read_env_optional("LEDGER_AUTHOR_NAME", env_path=self._env_path)
        email = read_env_optional("LEDGER_AUTHOR_EMAIL", env_path=self._env_path)
        try:
            name = name or repo.config["user.name"]
            email = email or repo.config["user.email"]
        except KeyError:
            pass
        name = name or _DEFAULT_LEDGER_AUTHOR_NAME
        email = email or _DEFAULT_LEDGER_AUTHOR_EMAIL
        return pygit2.Signature(name, email)

    def _open_repository(self) -> pygit2.Repository:
        """Open Archive repository backing this queue adapter."""

        return pygit2.Repository(str(self._repository_path))

    def _read_current_content(self, repo: pygit2.Repository) -> str:
        """Read current queue content from the branch, or empty if branch/file missing."""
        try:
            ref = repo.lookup_reference(self._queue_ref)
            commit = repo[ref.target]
        except (KeyError, pygit2.GitError):
            return ""
        if not isinstance(commit, pygit2.Commit):
            return ""
        path_parts = Path(_QUEUE_RELATIVE_PATH).parts
        try:
            tree = commit.tree
            for part in path_parts:
                entry = tree[part]
                obj = repo[entry.id]
                if isinstance(obj, pygit2.Blob):
                    return bytes(obj.data).decode("utf-8")
                tree = obj
        except KeyError:
            return ""
        return ""

    def _ensure_branch_exists(self, repo: pygit2.Repository) -> None:
        """Create branch with empty commit if it does not exist."""
        try:
            repo.lookup_reference(self._queue_ref)
            return
        except (KeyError, pygit2.GitError):
            pass
        builder = repo.TreeBuilder()
        tree_oid = builder.write()
        sig = self._resolve_commit_signature(repo)
        repo.create_commit(
            self._queue_ref,
            sig,
            sig,
            "provenance: init ots-queue",
            tree_oid,
            [],
        )
        _logger.info("Created branch %s for OTS queue", self._queue_ref)

    @staticmethod
    def _validate_jsonl(content: str) -> None:
        """Validate that content is valid JSONL (each non-empty line parses as JSON)."""
        for i, line in enumerate(content.splitlines()):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL: line {i + 1} is not valid JSON: {exc}") from exc

    def _commit_content(
        self,
        repo: pygit2.Repository,
        content: str,
        message: str,
    ) -> None:
        """Commit queue content to the branch."""
        self._validate_jsonl(content)
        self._ensure_branch_exists(repo)
        ref = repo.lookup_reference(self._queue_ref)
        parent = repo[ref.target]
        if not isinstance(parent, pygit2.Commit):
            raise RuntimeError(f"Branch {self._queue_ref} does not point to a commit.")
        path_parts = Path(_QUEUE_RELATIVE_PATH).parts
        blob_oid = repo.create_blob(content.encode("utf-8"))
        current_tree: pygit2.Tree | None = parent.tree
        tree_stack: list[pygit2.Tree | None] = [current_tree]
        for part in path_parts[:-1]:
            if current_tree is not None and part in current_tree:
                entry = current_tree[part]
                current_tree = repo[entry.id]
                if not isinstance(current_tree, pygit2.Tree):
                    raise RuntimeError(f"Path part '{part}' is not a directory.")
            else:
                current_tree = None
            tree_stack.append(current_tree)
        current_oid = blob_oid
        current_mode = pygit2.GIT_FILEMODE_BLOB
        for i, part in reversed(list(enumerate(path_parts))):
            tb = (
                repo.TreeBuilder(tree_stack[i]) if tree_stack[i] is not None else repo.TreeBuilder()
            )
            tb.insert(part, current_oid, current_mode)
            current_oid = tb.write()
            current_mode = pygit2.GIT_FILEMODE_TREE
        if current_oid == parent.tree_id:
            return
        sig = self._resolve_commit_signature(repo)
        repo.create_commit(
            self._queue_ref,
            sig,
            sig,
            message,
            current_oid,
            [parent.id],
        )

    def _append_event(self, new_line: str, commit_message: str) -> None:
        """Append one JSONL event line under lock and commit it."""

        lock_path = Path(str(self._queue_path) + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(lock_path):
            repo = self._open_repository()
            content = self._read_current_content(repo)
            new_content = (content.rstrip() + "\n" + new_line).lstrip()
            self._commit_content(
                repo=repo,
                content=new_content,
                message=commit_message,
            )
            line_count = sum(1 for line in new_content.splitlines() if line.strip())
            if (
                line_count > 0
                and line_count % _QUEUE_GROWTH_WARN_EVERY_LINES == 0
            ):
                _logger.warning(
                    "OTS queue has grown to %d events. Consider archival/compaction.",
                    line_count,
                )

    def append_pending(
        self,
        request_id: UUID | str,
        artifact_hash: str,
        pending_ots_b64: str,
    ) -> None:
        """Append a PENDING event and commit to Git."""
        rid = str(request_id)
        created = _utc_now_iso()
        new_line = json.dumps(
            {
                "event": "pending",
                "request_id": rid,
                "artifact_hash": artifact_hash,
                "pending_ots_b64": pending_ots_b64,
                "created_at": created,
                "updated_at": created,
            },
            sort_keys=True,
        )
        self._append_event(
            new_line=new_line,
            commit_message=f"provenance: OTS pending ({rid})",
        )

    def append_forged(
        self,
        request_id: UUID | str,
        bitcoin_block_height: int,
        artifact_hash: str | None = None,
        final_ots_b64: str | None = None,
    ) -> None:
        """Append a FORGED event and commit to Git.

        final_ots_b64 is optional; when provided, it is persisted as the final
        upgraded proof associated with this forge event.
        """
        rid = str(request_id)
        updated = _utc_now_iso()
        event_obj = {
            "event": "forged",
            "request_id": rid,
            "bitcoin_block_height": bitcoin_block_height,
            "updated_at": updated,
        }
        if artifact_hash:
            event_obj["artifact_hash"] = artifact_hash
        if final_ots_b64:
            event_obj["final_ots_b64"] = final_ots_b64
        new_line = json.dumps(event_obj, sort_keys=True)
        self._append_event(
            new_line=new_line,
            commit_message=f"provenance: OTS forged ({rid})",
        )

    def append_failed(
        self,
        request_id: UUID | str,
        failure_reason: str,
        artifact_hash: str | None = None,
    ) -> None:
        """Append a FAILED event and commit to Git."""
        rid = str(request_id)
        updated = _utc_now_iso()
        event_obj = {
            "event": "failed",
            "request_id": rid,
            "failure_reason": failure_reason,
            "updated_at": updated,
        }
        if artifact_hash:
            event_obj["artifact_hash"] = artifact_hash
        new_line = json.dumps(event_obj, sort_keys=True)
        self._append_event(
            new_line=new_line,
            commit_message=f"provenance: OTS failed ({rid})",
        )

    def _parse_events(self, content: str) -> dict[str, dict]:
        """Parse JSONL and return merged state per request_id (latest event wins)."""
        latest: dict[str, dict] = {}
        for line_index, line in enumerate(content.splitlines(), start=1):
            stripped_line = line.strip()
            if not stripped_line:
                continue
            try:
                obj = json.loads(stripped_line)
                rid = obj.get("request_id")
                if not rid:
                    _logger.warning(
                        "Skipping OTS queue line %d without request_id",
                        line_index,
                    )
                    continue
                existing = latest.get(rid, {})
                merged = {**existing, **obj}
                merged["event"] = obj.get("event", existing.get("event"))
                latest[rid] = merged
            except json.JSONDecodeError as exc:
                _logger.warning(
                    "Skipping malformed OTS queue JSON line %d: %s",
                    line_index,
                    exc,
                )
                continue
        return latest

    @staticmethod
    def _status_from_event(event: str | None) -> OtsForgeStatus | None:
        if event == "pending":
            return "PENDING"
        if event == "forged":
            return "FORGED"
        if event == "failed":
            return "FAILED"
        return None

    @staticmethod
    def _record_from_state(request_id: str, obj: dict) -> OtsForgeRecord | None:
        status = OtsQueueAdapter._status_from_event(obj.get("event"))
        if status is None:
            return None
        final_ots_b64 = obj.get("final_ots_b64") if status == "FORGED" else None
        block_height = obj.get("bitcoin_block_height") if status == "FORGED" else None
        return OtsForgeRecord(
            request_id=request_id,
            artifact_hash=obj.get("artifact_hash", ""),
            status=status,
            pending_ots_b64=obj.get("pending_ots_b64", ""),
            final_ots_b64=final_ots_b64,
            bitcoin_block_height=block_height,
            created_at=obj.get("created_at", ""),
            updated_at=obj.get("updated_at", ""),
        )

    def _load_latest_state(self) -> dict[str, dict]:
        """Load latest merged queue state from git-backed JSONL log."""

        repo = self._open_repository()
        content = self._read_current_content(repo)
        return self._parse_events(content)

    def get_pending_records(self, limit: int = 100) -> list[OtsForgeRecord]:
        """Return PENDING records (latest event is pending), as OtsForgeRecord."""
        latest = self._load_latest_state()
        pending: list[OtsForgeRecord] = []
        for rid, obj in latest.items():
            record = self._record_from_state(rid, obj)
            if record is None or record.status != "PENDING":
                continue
            if len(pending) >= limit:
                break
            pending.append(record)
        return pending

    def get_ots_forge_record(self, request_id: UUID) -> OtsForgeRecord | None:
        """Fetch one record by request_id. Returns None if not found."""
        latest = self._load_latest_state()
        obj = latest.get(str(request_id))
        if obj is None:
            return None
        return self._record_from_state(str(request_id), obj)

    def list_ots_forge_records(
        self,
        status: OtsForgeStatus | None = None,
        limit: int = 100,
    ) -> list[OtsForgeRecord]:
        """List records, optionally filtered by status, sorted by updated_at desc."""
        latest = self._load_latest_state()
        records: list[OtsForgeRecord] = []
        for rid, obj in latest.items():
            record = self._record_from_state(rid, obj)
            if record is None:
                continue
            if status is not None and record.status != status:
                continue
            records.append(record)
        records.sort(key=lambda r: r.updated_at or "", reverse=True)
        return records[:limit]

    def compact_queue(self, *, archive_path: Path) -> int:
        """Compact queue to latest-state events only, with explicit archive backup.

        This method is intentionally opt-in and requires an explicit archive path.
        It preserves archival safety by writing the full pre-compaction JSONL to
        archive_path before rewriting the queue.
        """

        lock_path = Path(str(self._queue_path) + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(lock_path):
            repo = self._open_repository()
            current_content = self._read_current_content(repo)
            if not current_content.strip():
                return 0

            archive_path.parent.mkdir(parents=True, exist_ok=True)
            archive_path.write_text(current_content, encoding="utf-8")

            latest = self._parse_events(current_content)
            compacted_lines = [
                json.dumps(obj, sort_keys=True)
                for _, obj in sorted(
                    latest.items(),
                    key=lambda item: (
                        str(item[1].get("updated_at", "")),
                        item[0],
                    ),
                )
            ]
            compacted_content = "\n".join(compacted_lines)
            if compacted_content:
                compacted_content = compacted_content + "\n"
            self._commit_content(
                repo=repo,
                content=compacted_content,
                message="provenance: compact ots-queue latest-state",
            )
            _logger.info(
                "Compacted OTS queue events=%d archive=%s",
                len(compacted_lines),
                archive_path,
            )
            return len(compacted_lines)
