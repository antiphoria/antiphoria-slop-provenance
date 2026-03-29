"""Git transparency ledger adapter using synchronous pygit2 primitives.

This adapter consumes `StorySigned`, renders strict Astro frontmatter Markdown,
and commits artifacts to a local repository through pygit2.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import binascii
import hashlib
import tempfile
from pathlib import Path

import pygit2
from filelock import FileLock

from src.artifact_serialization import render_artifact_markdown
from src.env_config import read_env_bool, read_env_optional
from src.events import EventBusPort, StoryCommitted, StorySigned
from src.logging_config import bind_log_context, should_log_route

_adapter_logger = logging.getLogger("src.adapters.git_ledger")
from src.models import sha256_hex
from src.secrets_guard import assert_secret_free

_DEFAULT_LEDGER_AUTHOR_NAME = "Antiphoria Slop Provenance"
_DEFAULT_LEDGER_AUTHOR_EMAIL = "bot@antiphoria.local"


class GitLedgerAdapter:
    """Event-driven git ledger publisher for signed artifacts."""

    def __init__(
        self,
        event_bus: EventBusPort,
        repository_path: Path | None = None,
        artifacts_directory: str = "",
        env_path: Path | None = None,
    ) -> None:
        """Initialize adapter and validate local git repository path.

        Args:
            event_bus: Shared asynchronous event bus instance.
            repository_path: Optional local git repository path.
            artifacts_directory: Optional relative directory for markdown artifacts.
            env_path: Optional path to .env for LEDGER_AUTHOR_NAME/EMAIL overrides.

        Raises:
            RuntimeError: If repository path is invalid or not a git repository.
        """

        self._event_bus = event_bus
        self._artifacts_directory = artifacts_directory.strip("/\\")
        self._repository_path = (repository_path or Path.cwd()).resolve()
        self._env_path = env_path or Path(".env")
        # Validate repository at startup; do not store. libgit2 repo pointers are
        # not thread-safe. Open repo inside each commit thread (see _commit_markdown_impl).
        self._open_repository(self._repository_path)
        self._enable_c2pa = read_env_bool(
            "ENABLE_C2PA",
            default=False,
            env_path=self._env_path,
        )

    async def start(self) -> None:
        """Subscribe to signed-story events."""

        await self._event_bus.subscribe(StorySigned, self._on_story_signed)

    async def _on_story_signed(self, event: StorySigned) -> None:
        """Render markdown and commit using pygit2.

        Args:
            event: Signed story payload emitted by the notary.
        """
        bind_log_context(request_id=event.request_id)

        self._assert_publishable_content_is_secret_free(event)
        markdown_payload = self._render_markdown(event)
        relative_path = self._build_relative_artifact_path(event)
        c2pa_sidecar_payload = self._resolve_c2pa_sidecar_payload(event)
        commit_message = f"ledger: notarize {event.artifact.title} ({event.request_id})"

        commit_oid = await asyncio.to_thread(
            self._commit_markdown_sync,
            str(event.request_id),
            relative_path,
            markdown_payload,
            c2pa_sidecar_payload,
            commit_message,
        )
        if should_log_route("coarse"):
            _adapter_logger.info(
                "GitLedgerAdapter emitting StoryCommitted request_id=%s",
                event.request_id,
                extra={"request_id": str(event.request_id)},
            )
        await self._event_bus.emit(
            StoryCommitted(
                request_id=event.request_id,
                ledger_path=relative_path,
                commit_oid=commit_oid,
            )
        )

    def _resolve_c2pa_sidecar_payload(self, event: StorySigned) -> bytes | None:
        """Resolve sidecar bytes from event payload with hash enforcement.

        When Notary produced C2PA bytes (event.c2pa_manifest_bytes_b64), persist them
        regardless of Ledger ENABLE_C2PA to avoid mode mismatch and corruption.
        """
        manifest_hash = event.c2pa_manifest_hash
        if manifest_hash is None and event.c2pa_manifest_bytes_b64 is not None:
            raise RuntimeError("C2PA sidecar bytes supplied without manifest hash.")
        if event.c2pa_manifest_bytes_b64 is not None:
            try:
                sidecar_payload = base64.b64decode(
                    event.c2pa_manifest_bytes_b64,
                    validate=True,
                )
            except binascii.Error as exc:
                raise RuntimeError("Invalid base64 C2PA sidecar payload.") from exc
            if manifest_hash is not None and sha256_hex(sidecar_payload) != manifest_hash:
                raise RuntimeError("C2PA manifest hash mismatch while writing sidecar bytes.")
            return sidecar_payload
        if not self._enable_c2pa or manifest_hash is None:
            return None
        raise RuntimeError(
            "C2PA manifest bytes required. Event must carry c2pa_manifest_bytes_b64."
        )

    @staticmethod
    def _assert_publishable_content_is_secret_free(event: StorySigned) -> None:
        """Block publication if prompt/body contains secret-like material."""

        try:
            generation_context = event.artifact.provenance.generation_context
            assert_secret_free("generation prompt", generation_context.prompt)
            assert_secret_free("system instruction", generation_context.system_instruction)
            assert_secret_free("artifact body", event.body)
        except RuntimeError as exc:
            raise RuntimeError(f"{exc} request_id={event.request_id}") from exc

    def _open_repository(self, repository_path: Path) -> pygit2.Repository:
        """Open and validate the target git repository.

        Args:
            repository_path: Filesystem path expected to contain a git repo.

        Returns:
            Open pygit2 repository.

        Raises:
            RuntimeError: If the path is invalid or not a git repository.
        """

        if not repository_path.exists():
            raise RuntimeError(f"Invalid git repository path: '{repository_path}'.")

        try:
            return pygit2.Repository(str(repository_path))
        except (KeyError, pygit2.GitError) as exc:
            raise RuntimeError(f"Invalid git repository path: '{repository_path}'.") from exc

    def _build_relative_artifact_path(self, event: StorySigned) -> str:
        """Build deterministic repo-relative artifact markdown path."""

        filename = f"{event.request_id}.md"
        if not self._artifacts_directory:
            return filename
        return f"{self._artifacts_directory}/{filename}"

    def _render_markdown(self, event: StorySigned) -> str:
        """Render artifact markdown with strict frontmatter schema. No PEM footers."""
        return render_artifact_markdown(event.artifact, event.body)

    def _resolve_commit_signature(self, repo: pygit2.Repository) -> pygit2.Signature:
        """Resolve git author/committer signature.

        Priority: LEDGER_AUTHOR_NAME/EMAIL (env or .env) > git config > default bot.
        Use env overrides to avoid burning personal PII into the public ledger.
        """

        name = read_env_optional("LEDGER_AUTHOR_NAME", env_path=self._env_path)
        email = read_env_optional("LEDGER_AUTHOR_EMAIL", env_path=self._env_path)
        if name and email:
            return pygit2.Signature(name, email)
        try:
            name = name or repo.config["user.name"]
            email = email or repo.config["user.email"]
        except KeyError:
            pass
        name = name or _DEFAULT_LEDGER_AUTHOR_NAME
        email = email or _DEFAULT_LEDGER_AUTHOR_EMAIL
        return pygit2.Signature(name, email)

    def _commit_markdown_sync(
        self,
        request_id: str,
        relative_path: str,
        markdown_payload: str,
        c2pa_sidecar_payload: bytes | None,
        commit_message: str,
    ) -> str:
        """Synchronously write blob/tree and create branch-isolated commit.

        Uses FileLock keyed by repo hash + branch (same as ProvenanceService)
        to prevent Git index deadlock when both adapters commit to same branch.

        Args:
            request_id: Correlation id used to derive branch name.
            relative_path: Repository-relative markdown file path.
            markdown_payload: Markdown body to persist as git blob.
            commit_message: Commit message text.

        Returns:
            Created commit object id as hex string.
        """
        branch_name = f"artifact/{request_id}"
        ref_name = f"refs/heads/{branch_name}"
        repo_hash = hashlib.sha256(str(self._repository_path.resolve()).encode()).hexdigest()[:16]
        lock_dir = Path(tempfile.gettempdir()) / "antiphoria-slop-provenance" / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        lock_path = lock_dir / f"{repo_hash}_{ref_name.replace('/', '_')}.lock"
        with FileLock(lock_path):
            return self._commit_markdown_impl(
                request_id=request_id,
                relative_path=relative_path,
                markdown_payload=markdown_payload,
                c2pa_sidecar_payload=c2pa_sidecar_payload,
                commit_message=commit_message,
                ref_name=ref_name,
            )

    def _commit_markdown_impl(
        self,
        request_id: str,
        relative_path: str,
        markdown_payload: str,
        c2pa_sidecar_payload: bytes | None,
        commit_message: str,
        ref_name: str,
    ) -> str:
        """Inner commit logic (caller holds FileLock)."""
        repo = self._open_repository(self._repository_path)
        parent_commit = self._get_branch_head(repo, ref_name)

        tree_id = self._build_root_tree_oid(
            repo=repo,
            relative_path=relative_path,
            markdown_payload=markdown_payload,
            c2pa_sidecar_payload=c2pa_sidecar_payload,
            parent_tree_oid=parent_commit.tree_id if parent_commit else None,
        )

        signature = self._resolve_commit_signature(repo)
        parents: list[pygit2.Oid] = [parent_commit.id] if parent_commit else []
        if parent_commit is not None and parent_commit.tree_id == tree_id:
            return str(parent_commit.id)

        commit_id = repo.create_commit(
            ref_name,
            signature,
            signature,
            commit_message,
            tree_id,
            parents,
        )
        return str(commit_id)

    def _get_branch_head(self, repo: pygit2.Repository, ref_name: str) -> pygit2.Commit | None:
        """Return current branch head commit for a given ref name."""

        try:
            reference = repo.lookup_reference(ref_name)
        except KeyError:
            return None
        target = repo[reference.target]
        if not isinstance(target, pygit2.Commit):
            raise RuntimeError(f"Invalid branch head object for ref '{ref_name}'.")
        return target

    def _build_root_tree_oid(
        self,
        repo: pygit2.Repository,
        relative_path: str,
        markdown_payload: str,
        c2pa_sidecar_payload: bytes | None,
        parent_tree_oid: pygit2.Oid | None = None,
    ) -> pygit2.Oid:
        """Build root tree with artifact files, preserving parent tree (e.g. .provenance)."""

        path_obj = Path(relative_path)
        if ".." in path_obj.parts or path_obj.is_absolute():
            raise RuntimeError(
                f"Invalid artifact path '{relative_path}': parent traversal and "
                "absolute paths are not allowed."
            )
        parent_dir = path_obj.parent.as_posix()
        if self._artifacts_directory:
            if parent_dir != self._artifacts_directory:
                raise RuntimeError(
                    f"Invalid artifact path '{relative_path}'. Expected directory "
                    f"'{self._artifacts_directory}/'."
                )
        elif parent_dir != ".":
            raise RuntimeError(
                f"Invalid artifact path '{relative_path}'. Expected repository root."
            )

        blob_oid = repo.create_blob(markdown_payload.encode("utf-8"))
        if not self._artifacts_directory:
            root_tb = (
                repo.TreeBuilder(parent_tree_oid)
                if parent_tree_oid is not None
                else repo.TreeBuilder()
            )
            root_tb.insert(path_obj.name, blob_oid, pygit2.GIT_FILEMODE_BLOB)
            if c2pa_sidecar_payload is not None:
                sidecar_blob_oid = repo.create_blob(c2pa_sidecar_payload)
                sidecar_name = f"{path_obj.stem}.c2pa"
                root_tb.insert(sidecar_name, sidecar_blob_oid, pygit2.GIT_FILEMODE_BLOB)
            return root_tb.write()

        parent_tree = repo[parent_tree_oid] if parent_tree_oid else None
        artifacts_parent_oid: pygit2.Oid | None = None
        if parent_tree is not None and self._artifacts_directory:
            parts = self._artifacts_directory.split("/")
            current: pygit2.Tree | None = parent_tree
            for part in parts:
                if current is None or part not in current:
                    break
                entry = current[part]
                if not entry:
                    break
                obj = repo[entry.id]
                if isinstance(obj, pygit2.Tree):
                    current = obj
                    artifacts_parent_oid = obj.id
                else:
                    break
        artifacts_tb = (
            repo.TreeBuilder(artifacts_parent_oid)
            if artifacts_parent_oid is not None
            else repo.TreeBuilder()
        )
        artifacts_tb.insert(path_obj.name, blob_oid, pygit2.GIT_FILEMODE_BLOB)
        if c2pa_sidecar_payload is not None:
            sidecar_blob_oid = repo.create_blob(c2pa_sidecar_payload)
            sidecar_name = f"{path_obj.stem}.c2pa"
        artifacts_tb.insert(sidecar_name, sidecar_blob_oid, pygit2.GIT_FILEMODE_BLOB)
        artifacts_oid = artifacts_tb.write()

        # Git trees are single-level; insert expects one path component.
        # For nested artifacts_directory (e.g. docs/artifacts), build bottom-up.
        path_parts = self._artifacts_directory.split("/")
        if len(path_parts) == 1:
            root_tb = (
                repo.TreeBuilder(parent_tree_oid)
                if parent_tree_oid is not None
                else repo.TreeBuilder()
            )
            root_tb.insert(self._artifacts_directory, artifacts_oid, pygit2.GIT_FILEMODE_TREE)
            return root_tb.write()

        # Nested path: traverse down to build tree_stack, then build up.
        current_tree: pygit2.Tree | None = parent_tree
        tree_stack: list[pygit2.Tree | None] = [current_tree]
        for part in path_parts[:-1]:
            if current_tree is not None and part in current_tree:
                entry = current_tree[part]
                obj = repo[entry.id]
                if isinstance(obj, pygit2.Tree):
                    current_tree = obj
                else:
                    current_tree = None
            else:
                current_tree = None
            tree_stack.append(current_tree)

        current_oid = artifacts_oid
        current_mode = pygit2.GIT_FILEMODE_TREE
        for i, part in reversed(list(enumerate(path_parts))):
            tb = (
                repo.TreeBuilder(tree_stack[i]) if tree_stack[i] is not None else repo.TreeBuilder()
            )
            tb.insert(part, current_oid, current_mode)
            current_oid = tb.write()
            current_mode = pygit2.GIT_FILEMODE_TREE
        return current_oid
