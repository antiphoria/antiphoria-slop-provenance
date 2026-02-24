"""Git transparency ledger adapter using synchronous pygit2 primitives.

This adapter consumes `StorySigned`, renders strict Astro frontmatter Markdown,
and commits artifacts to a local repository through pygit2.
"""

from __future__ import annotations

import asyncio
import textwrap
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
            str(event.request_id),
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

        filename = f"{event.request_id}.md"
        return f"{self._artifacts_directory}/{filename}"

    @staticmethod
    def _wrap_signature_lines(signature_base64: str, line_width: int = 76) -> list[str]:
        """Normalize and wrap base64 signature text for YAML/footer blocks."""

        condensed = "".join(signature_base64.split())
        if not condensed:
            raise RuntimeError("Artifact signature cannot be empty.")
        return textwrap.wrap(condensed, width=line_width)

    @staticmethod
    def _yaml_folded_block(text: str, indent: int) -> str:
        """Render text using YAML folded block scalar semantics."""

        prefix = " " * indent
        lines = text.splitlines() or [text]
        return "\n".join(f"{prefix}{line}" for line in lines)

    @staticmethod
    def _yaml_literal_block(text: str, indent: int) -> str:
        """Render text using YAML literal block scalar semantics."""

        prefix = " " * indent
        lines = text.splitlines() or [text]
        return "\n".join(f"{prefix}{line}" for line in lines)

    def _render_markdown(self, event: StorySigned) -> str:
        """Render artifact markdown with strict frontmatter schema.

        Args:
            event: Signed event containing frontmatter payload and body.

        Returns:
            Markdown text formatted for Astro parsing.
        """

        artifact = event.artifact
        if artifact.signature is None:
            raise RuntimeError("Signed artifact envelope is missing signature block.")
        signature_lines = self._wrap_signature_lines(
            artifact.signature.cryptographic_signature
        )
        signature_block_yaml = "\n".join(f"    {line}" for line in signature_lines)
        signature_block_footer = "\n".join(signature_lines)
        prompt_block_yaml = self._yaml_folded_block(
            artifact.provenance.generation_context.prompt,
            indent=6,
        )
        system_instruction_yaml = self._yaml_folded_block(
            artifact.provenance.generation_context.system_instruction,
            indent=6,
        )

        curation_block = ""
        if artifact.curation is not None:
            diff_block = self._yaml_literal_block(artifact.curation.unified_diff, indent=6)
            curation_block = (
                "curation:\n"
                f"  differenceScore: {artifact.curation.difference_score:.2f}\n"
                "  unifiedDiff: |\n"
                f"{diff_block}\n"
            )
        else:
            curation_block = "curation: null\n"

        usage_block = ""
        if artifact.provenance.usage_metrics is not None:
            usage = artifact.provenance.usage_metrics
            usage_block = (
                "  usageMetrics:\n"
                f"    promptTokens: {usage.prompt_tokens}\n"
                f"    completionTokens: {usage.completion_tokens}\n"
                f"    totalTokens: {usage.total_tokens}\n"
            )

        watermark_block = ""
        if artifact.provenance.embedded_watermark is not None:
            watermark = artifact.provenance.embedded_watermark
            watermark_block = (
                "  embeddedWatermark:\n"
                f'    provider: "{watermark.provider}"\n'
                f'    status: "{watermark.status}"\n'
            )

        public_key_uri_line = ""
        if artifact.signature.verification_anchor.public_key_uri is not None:
            public_key_uri_line = (
                f'    publicKeyUri: "{artifact.signature.verification_anchor.public_key_uri}"\n'
            )

        return (
            "---\n"
            f'schemaVersion: "{artifact.schema_version}"\n'
            f'id: "{artifact.id}"\n'
            f'title: "{artifact.title}"\n'
            f'timestamp: "{artifact.timestamp.isoformat()}"\n'
            f'contentType: "{artifact.content_type}"\n'
            f'license: "{artifact.license}"\n'
            "provenance:\n"
            f'  source: "{artifact.provenance.source}"\n'
            f'  engineVersion: "{artifact.provenance.engine_version}"\n'
            f'  modelId: "{artifact.provenance.model_id}"\n'
            "  generationContext:\n"
            "    systemInstruction: >\n"
            f"{system_instruction_yaml}\n"
            "    prompt: >\n"
            f"{prompt_block_yaml}\n"
            "    hyperparameters:\n"
            f"      temperature: {artifact.provenance.generation_context.hyperparameters.temperature}\n"
            f"      topP: {artifact.provenance.generation_context.hyperparameters.top_p}\n"
            f"      topK: {artifact.provenance.generation_context.hyperparameters.top_k}\n"
            f"{usage_block}"
            f"{watermark_block}"
            f"{curation_block}"
            "signature:\n"
            f'  cryptoAlgorithm: "{artifact.signature.crypto_algorithm}"\n'
            f'  artifactHash: "{artifact.signature.artifact_hash}"\n'
            "  verificationAnchor:\n"
            f'    signerFingerprint: "{artifact.signature.verification_anchor.signer_fingerprint}"\n'
            f"{public_key_uri_line}"
            "  cryptographicSignature: |\n"
            f"{signature_block_yaml}\n"
            f'recordStatus: "{artifact.record_status}"\n'
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
        request_id: str,
        relative_path: str,
        markdown_payload: str,
        commit_message: str,
    ) -> str:
        """Synchronously write blob/tree and create branch-isolated commit.

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
        parent_commit = self._get_branch_head(ref_name)

        tree_id = self._build_root_tree_oid(relative_path, markdown_payload)

        signature = self._resolve_commit_signature()
        parents: list[pygit2.Oid] = [parent_commit.id] if parent_commit else []

        commit_id = self._repo.create_commit(
            ref_name,
            signature,
            signature,
            commit_message,
            tree_id,
            parents,
        )
        return str(commit_id)

    def _get_branch_head(self, ref_name: str) -> pygit2.Commit | None:
        """Return current branch head commit for a given ref name."""

        try:
            reference = self._repo.lookup_reference(ref_name)
        except KeyError:
            return None
        target = self._repo[reference.target]
        if not isinstance(target, pygit2.Commit):
            raise RuntimeError(f"Invalid branch head object for ref '{ref_name}'.")
        return target

    def _build_root_tree_oid(self, relative_path: str, markdown_payload: str) -> pygit2.Oid:
        """Build a strict two-level ODB tree for artifacts/<request_id>.md."""

        path_obj = Path(relative_path)
        if path_obj.parent.as_posix() != self._artifacts_directory:
            raise RuntimeError(
                f"Invalid artifact path '{relative_path}'. Expected directory "
                f"'{self._artifacts_directory}/'."
            )

        blob_oid = self._repo.create_blob(markdown_payload.encode("utf-8"))
        artifacts_tb = self._repo.TreeBuilder()
        artifacts_tb.insert(path_obj.name, blob_oid, pygit2.GIT_FILEMODE_BLOB)
        artifacts_oid = artifacts_tb.write()

        root_tb = self._repo.TreeBuilder()
        root_tb.insert(self._artifacts_directory, artifacts_oid, pygit2.GIT_FILEMODE_TREE)
        return root_tb.write()
