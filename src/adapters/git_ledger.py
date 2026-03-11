"""Git transparency ledger adapter using synchronous pygit2 primitives.

This adapter consumes `StorySigned`, renders strict Astro frontmatter Markdown,
and commits artifacts to a local repository through pygit2.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import textwrap
from pathlib import Path

import pygit2

from src.adapters.c2pa_manifest import build_c2pa_sidecar_manifest
from src.env_config import read_env_bool, read_env_optional
from src.events import EventBusPort, StoryCommitted, StorySigned
from src.models import sha256_hex
from src.secrets_guard import assert_secret_free

_DEFAULT_LEDGER_AUTHOR_NAME = "Slop Orchestrator"
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
        self._repo = self._open_repository(self._repository_path)
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

        self._assert_publishable_content_is_secret_free(event)
        markdown_payload = self._render_markdown(event)
        relative_path = self._build_relative_artifact_path(event)
        c2pa_sidecar_payload = self._resolve_c2pa_sidecar_payload(event)
        commit_message = (
            f"ledger: notarize {event.artifact.title} " f"({event.request_id})"
        )

        commit_oid = await asyncio.to_thread(
            self._commit_markdown_sync,
            str(event.request_id),
            relative_path,
            markdown_payload,
            c2pa_sidecar_payload,
            commit_message,
        )
        await self._event_bus.emit(
            StoryCommitted(
                request_id=event.request_id,
                ledger_path=relative_path,
                commit_oid=commit_oid,
            )
        )

    def _resolve_c2pa_sidecar_payload(self, event: StorySigned) -> bytes | None:
        """Resolve sidecar bytes from event payload with hash enforcement."""

        if not self._enable_c2pa:
            return None

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
            if (
                manifest_hash is not None
                and sha256_hex(sidecar_payload) != manifest_hash
            ):
                raise RuntimeError(
                    "C2PA manifest hash mismatch while writing sidecar bytes."
                )
            return sidecar_payload
        if manifest_hash is None:
            return None
        # Backward-compatibility path: old events only carried hash, not bytes.
        c2pa_artifact = build_c2pa_sidecar_manifest(
            event.artifact,
            event.body,
            env_path=self._env_path,
        )
        if c2pa_artifact.manifest_hash != manifest_hash:
            raise RuntimeError("C2PA manifest hash mismatch while writing sidecar.")
        return c2pa_artifact.manifest_bytes

    @staticmethod
    def _assert_publishable_content_is_secret_free(event: StorySigned) -> None:
        """Block publication if prompt/body contains secret-like material."""

        try:
            generation_context = event.artifact.provenance.generation_context
            assert_secret_free("generation prompt", generation_context.prompt)
            assert_secret_free(
                "system instruction", generation_context.system_instruction
            )
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
            raise RuntimeError(
                f"Invalid git repository path: '{repository_path}'."
            ) from exc

    def _build_relative_artifact_path(self, event: StorySigned) -> str:
        """Build deterministic repo-relative artifact markdown path."""

        filename = f"{event.request_id}.md"
        if not self._artifacts_directory:
            return filename
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

    @staticmethod
    def _yaml_quoted(value: str) -> str:
        """Render one YAML-safe quoted scalar using JSON escaping rules."""

        return json.dumps(value, ensure_ascii=False)

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
        prompt_block_yaml = self._yaml_literal_block(
            artifact.provenance.generation_context.prompt,
            indent=6,
        )
        system_instruction_yaml = self._yaml_literal_block(
            artifact.provenance.generation_context.system_instruction,
            indent=6,
        )

        curation_block = ""
        if artifact.curation is not None:
            diff_block = self._yaml_literal_block(
                artifact.curation.unified_diff, indent=6
            )
            curation_block = (
                "curation:\n"
                f"  differenceScore: {artifact.curation.difference_score:.2f}\n"
                "  unifiedDiff: |-\n"
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
                f"    provider: {self._yaml_quoted(watermark.provider)}\n"
                f"    status: {self._yaml_quoted(watermark.status)}\n"
            )

        attestation_block = ""
        if artifact.provenance.author_attestation is not None:
            att = artifact.provenance.author_attestation
            attestation_block = (
                "  authorAttestation:\n"
                f"    classification: {self._yaml_quoted(att.classification)}\n"
                f"    isHuman: {str(att.is_human).lower()}\n"
                f"    isOriginalCreation: {str(att.is_original_creation).lower()}\n"
                f"    isIndependentAndAccurate: {str(att.is_independent_and_accurate).lower()}\n"
                f"    understandsCryptographicPermanence: {str(att.understands_cryptographic_permanence).lower()}\n"
            )

        public_key_uri_line = ""
        if artifact.signature.verification_anchor.public_key_uri is not None:
            public_key_uri_line = (
                "    publicKeyUri: "
                f"{self._yaml_quoted(str(artifact.signature.verification_anchor.public_key_uri))}\n"
            )

        return (
            "---\n"
            f"schemaVersion: {self._yaml_quoted(artifact.schema_version)}\n"
            f"id: {self._yaml_quoted(str(artifact.id))}\n"
            f"title: {self._yaml_quoted(artifact.title)}\n"
            f"timestamp: {self._yaml_quoted(artifact.timestamp.isoformat())}\n"
            f"contentType: {self._yaml_quoted(artifact.content_type)}\n"
            f"license: {self._yaml_quoted(str(artifact.license))}\n"
            "provenance:\n"
            f"  source: {self._yaml_quoted(artifact.provenance.source)}\n"
            f"  engineVersion: {self._yaml_quoted(artifact.provenance.engine_version)}\n"
            f"  modelId: {self._yaml_quoted(artifact.provenance.model_id)}\n"
            "  generationContext:\n"
            "    systemInstruction: |-\n"
            f"{system_instruction_yaml}\n"
            "    prompt: |-\n"
            f"{prompt_block_yaml}\n"
            "    hyperparameters:\n"
            f"      temperature: {artifact.provenance.generation_context.hyperparameters.temperature}\n"
            f"      topP: {artifact.provenance.generation_context.hyperparameters.top_p}\n"
            f"      topK: {artifact.provenance.generation_context.hyperparameters.top_k}\n"
            f"{usage_block}"
            f"{watermark_block}"
            f"{attestation_block}"
            f"{curation_block}"
            "signature:\n"
            f"  cryptoAlgorithm: {self._yaml_quoted(artifact.signature.crypto_algorithm)}\n"
            f"  artifactHash: {self._yaml_quoted(artifact.signature.artifact_hash)}\n"
            "  verificationAnchor:\n"
            "    signerFingerprint: "
            f"{self._yaml_quoted(artifact.signature.verification_anchor.signer_fingerprint)}\n"
            f"{public_key_uri_line}"
            "  cryptographicSignature: |\n"
            f"{signature_block_yaml}\n"
            f"recordStatus: {self._yaml_quoted(artifact.record_status)}\n"
            "---\n"
            f"{event.body}\n"
            "-----BEGIN ANTIPHORIA ARTIFACT SIGNATURE-----\n"
            "Hash: SHA256\n"
            f"Algorithm: {artifact.signature.crypto_algorithm}\n"
            f"{signature_block_footer}\n"
            "-----END ANTIPHORIA ARTIFACT SIGNATURE-----\n"
        )

    def _resolve_commit_signature(self) -> pygit2.Signature:
        """Resolve git author/committer signature.

        Priority: LEDGER_AUTHOR_NAME/EMAIL (env or .env) > git config > default bot.
        Use env overrides to avoid burning personal PII into the public ledger.
        """

        name = read_env_optional("LEDGER_AUTHOR_NAME", env_path=self._env_path)
        email = read_env_optional("LEDGER_AUTHOR_EMAIL", env_path=self._env_path)
        if name and email:
            return pygit2.Signature(name, email)
        try:
            name = name or self._repo.config["user.name"]
            email = email or self._repo.config["user.email"]
        except KeyError:
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

        tree_id = self._build_root_tree_oid(
            relative_path=relative_path,
            markdown_payload=markdown_payload,
            c2pa_sidecar_payload=c2pa_sidecar_payload,
            parent_tree_oid=parent_commit.tree_id if parent_commit else None,
        )

        signature = self._resolve_commit_signature()
        parents: list[pygit2.Oid] = [parent_commit.id] if parent_commit else []
        if parent_commit is not None and parent_commit.tree_id == tree_id:
            return str(parent_commit.id)

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

    def _build_root_tree_oid(
        self,
        relative_path: str,
        markdown_payload: str,
        c2pa_sidecar_payload: bytes | None,
        parent_tree_oid: pygit2.Oid | None = None,
    ) -> pygit2.Oid:
        """Build root tree with artifact files, preserving parent tree (e.g. .provenance)."""

        path_obj = Path(relative_path)
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

        blob_oid = self._repo.create_blob(markdown_payload.encode("utf-8"))
        if not self._artifacts_directory:
            root_tb = (
                self._repo.TreeBuilder(parent_tree_oid)
                if parent_tree_oid is not None
                else self._repo.TreeBuilder()
            )
            root_tb.insert(path_obj.name, blob_oid, pygit2.GIT_FILEMODE_BLOB)
            if c2pa_sidecar_payload is not None:
                sidecar_blob_oid = self._repo.create_blob(c2pa_sidecar_payload)
                sidecar_name = f"{path_obj.stem}.c2pa"
                root_tb.insert(sidecar_name, sidecar_blob_oid, pygit2.GIT_FILEMODE_BLOB)
            return root_tb.write()

        parent_tree = self._repo[parent_tree_oid] if parent_tree_oid else None
        artifacts_tb = (
            self._repo.TreeBuilder(parent_tree[self._artifacts_directory].id)
            if parent_tree is not None
            and self._artifacts_directory in parent_tree
            else self._repo.TreeBuilder()
        )
        artifacts_tb.insert(path_obj.name, blob_oid, pygit2.GIT_FILEMODE_BLOB)
        if c2pa_sidecar_payload is not None:
            sidecar_blob_oid = self._repo.create_blob(c2pa_sidecar_payload)
            sidecar_name = f"{path_obj.stem}.c2pa"
            artifacts_tb.insert(
                sidecar_name, sidecar_blob_oid, pygit2.GIT_FILEMODE_BLOB
            )
        artifacts_oid = artifacts_tb.write()
        root_tb = (
            self._repo.TreeBuilder(parent_tree_oid)
            if parent_tree_oid is not None
            else self._repo.TreeBuilder()
        )
        root_tb.insert(
            self._artifacts_directory, artifacts_oid, pygit2.GIT_FILEMODE_TREE
        )
        return root_tb.write()
