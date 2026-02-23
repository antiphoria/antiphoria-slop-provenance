"""Git transparency ledger adapter using synchronous pygit2 primitives.

This adapter consumes `StorySigned`, renders strict Astro frontmatter Markdown,
and commits artifacts to a local repository through pygit2.
"""

from __future__ import annotations

import asyncio
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pygit2

from src.events import EventBus, StoryCommitted, StorySigned


class GitLedgerAdapter:
    """Event-driven git ledger publisher for signed artifacts."""

    def __init__(
        self,
        event_bus: EventBus,
        repository_path: Path | None = None,
        artifacts_directory: str = "artifacts",
    ) -> None:
        """Initialize adapter and validate local git repository path.

        Args:
            event_bus: Shared asynchronous event bus instance.
            repository_path: Optional local git repository path.
            artifacts_directory: Relative directory for markdown artifacts.

        Raises:
            RuntimeError: If repository path is invalid or not a git repository.
        """

        self._event_bus = event_bus
        self._artifacts_directory = artifacts_directory.strip("/\\")
        self._repository_path = (repository_path or Path.cwd()).resolve()
        self._repo = self._open_repository(self._repository_path)

    async def start(self) -> None:
        """Subscribe to signed-story events."""

        await self._event_bus.subscribe(StorySigned, self._on_story_signed)

    async def _on_story_signed(self, event: StorySigned) -> None:
        """Render markdown and commit using pygit2.

        Args:
            event: Signed story payload emitted by the notary.
        """

        markdown_payload = self._render_markdown(event)
        relative_path = self._build_relative_artifact_path(event)
        commit_message = (
            f"ledger: notarize {event.artifact.title} "
            f"({event.request_id})"
        )

        commit_oid = await asyncio.to_thread(
            self._commit_markdown_sync,
            relative_path,
            markdown_payload,
            commit_message,
        )
        await self._event_bus.emit(
            StoryCommitted(
                request_id=event.request_id,
                ledger_path=relative_path,
                commit_oid=commit_oid,
            )
        )

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
            raise RuntimeError(
                f"Invalid git repository path: '{repository_path}'."
            ) from exc

    def _build_relative_artifact_path(self, event: StorySigned) -> str:
        """Build deterministic repo-relative artifact markdown path."""

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{timestamp}_{event.request_id}.md"
        return f"{self._artifacts_directory}/{filename}"

    @staticmethod
    def _wrap_signature_lines(signature_base64: str, line_width: int = 76) -> list[str]:
        """Normalize and wrap base64 signature text for YAML/footer blocks."""

        condensed = "".join(signature_base64.split())
        if not condensed:
            raise RuntimeError("Artifact signature cannot be empty.")
        return textwrap.wrap(condensed, width=line_width)

    def _render_markdown(self, event: StorySigned) -> str:
        """Render artifact markdown with strict frontmatter schema.

        Args:
            event: Signed event containing frontmatter payload and body.

        Returns:
            Markdown text formatted for Astro parsing.
        """

        artifact = event.artifact
        signature_lines = self._wrap_signature_lines(
            artifact.provenance.cryptographic_signature
        )
        signature_block_yaml = "\n".join(f"    {line}" for line in signature_lines)
        signature_block_footer = "\n".join(signature_lines)

        return (
            "---\n"
            f'title: "{artifact.title}"\n'
            "provenance:\n"
            f'  source: "{artifact.provenance.source}"\n'
            f'  modelId: "{artifact.provenance.model_id}"\n'
            f'  artifactHash: "{artifact.provenance.artifact_hash}"\n'
            f'  cryptoAlgorithm: "{artifact.provenance.crypto_algorithm}"\n'
            "  cryptographicSignature: |\n"
            f"{signature_block_yaml}\n"
            f'  recordStatus: "{artifact.record_status}"\n'
            "---\n"
            f"{event.body}\n"
            "-----BEGIN ANTINOMIE-INSTITUT ARTIFACT SIGNATURE-----\n"
            "Hash: SHA256\n"
            "Algorithm: CRYSTALS-Dilithium\n"
            f"{signature_block_footer}\n"
            "-----END ANTINOMIE-INSTITUT ARTIFACT SIGNATURE-----\n"
        )

    def _resolve_commit_signature(self) -> pygit2.Signature:
        """Resolve git author/committer signature from repository config."""

        try:
            name = self._repo.config["user.name"]
            email = self._repo.config["user.email"]
        except KeyError as exc:
            raise RuntimeError(
                "Git user identity is missing. Configure 'user.name' and "
                "'user.email' for the ledger repository."
            ) from exc

        return pygit2.Signature(name, email)

    def _commit_markdown_sync(
        self,
        relative_path: str,
        markdown_payload: str,
        commit_message: str,
    ) -> str:
        """Synchronously write blob/tree and create commit in local repo.

        Args:
            relative_path: Repository-relative markdown file path.
            markdown_payload: Markdown body to persist as git blob.
            commit_message: Commit message text.

        Returns:
            Created commit object id as hex string.
        """
        artifact_path = self._repository_path / Path(relative_path)
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(markdown_payload, encoding="utf-8")

        index = self._repo.index
        index.read()
        index.add(Path(relative_path).as_posix())
        index.write()
        tree_id = index.write_tree()

        signature = self._resolve_commit_signature()
        parents: list[pygit2.Oid] = []
        if not self._repo.head_is_unborn:
            parents = [self._repo.head.target]

        commit_id = self._repo.create_commit(
            "HEAD",
            signature,
            signature,
            commit_message,
            tree_id,
            parents,
        )
        return str(commit_id)
