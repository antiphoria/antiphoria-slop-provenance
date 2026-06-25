"""Verification service for full-chain provenance audit reports."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

import pygit2

from src.adapters.c2pa_manifest import (
    build_c2pa_validation_payload,
    validate_c2pa_sidecar,
)
from src.adapters.catalog import CatalogAdapter
from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.ots_adapter import OTSAdapter
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter
from src.adapters.transparency_log import (
    TransparencyLogAdapter,
    TransparencyLogEntry,
)
from src.canonicalization import canonicalize_body_for_hash, compute_payload_hash
from src.envelope_v2 import parse_sidecars_from_markdown
from src.git_tree_utils import tree_get_blob
from src.logging_config import bind_log_context, get_log_extra, should_log_route
from src.models import Artifact, sha256_hex
from src.parsing import (
    parse_artifact_markdown,
    parse_artifact_markdown_text,
)
from src.services.curation_service import extract_request_id_from_artifact_path

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditReport:
    """Machine-readable audit report schema."""

    artifact_id: str
    request_id: str | None
    source_file: str
    envelope_valid: bool
    signature_valid: bool
    payload_hash_match: bool
    transparency_anchor_found: bool
    transparency_log_integrity: bool
    timestamp_found: bool
    timestamp_valid: bool
    key_status_at_signing_time: str
    # v3: remote_anchor_verified was removed (Supabase code gone, pre-release.md §1).
    # Kept as a field so legacy JSON reports still parse; always None for new audits.
    remote_anchor_verified: bool | None = None
    c2pa_present: bool = False
    c2pa_valid: bool = False
    c2pa_validation_state: str | None = None
    c2pa_errors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    branch: str | None = None
    commit_oid: str | None = None
    ledger_path: str | None = None
    ots_forged: bool = False
    bitcoin_block_height: int | None = None
    unattended_ceremony: bool = False
    webauthn_present: bool = False
    # v3 (Flaw A): distinguishes "block exists" from "cryptographically verified".
    # webauthn_verified is True only after a successful ES256 verify against the
    # published credential public key, RP ID hash, and challenge. Legacy v2
    # artifacts (no clientDataJson) report present=True, verified=False.
    webauthn_verified: bool = False
    webauthn_verify_skipped: str | None = None
    ots_sidecar_declared: bool = False
    ots_blob_present: bool = False
    # v3 (Gap 1): supersession state from the catalog row. None = unknown / no
    # catalog row. A non-empty string = requestId of the newer version that
    # supersedes this one. Surfaced as a WARN (not FAIL) — the artifact is
    # honest, just no longer current.
    superseded_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert report dataclass to serializable dictionary."""

        return asdict(self)


class ArtifactVerifierPort(Protocol):
    """Port for artifact signature verification."""

    def verify_artifact_payload(
        self,
        envelope: Artifact,
        payload: str,
        manifest_hash: str | None,
    ) -> bool:
        """Verify one parsed envelope+payload pair."""


class AuditStorePort(Protocol):
    """Narrow persistence contract for machine-readable audit reports."""

    def create_audit_report(
        self,
        artifact_id: str,
        request_id: str | None,
        report_json: str,
    ) -> str: ...


class VerificationService:
    """Orchestrates envelope, signature, anchor, timestamp, and key checks."""

    def __init__(
        self,
        audit_store: AuditStorePort,
        transparency_log_adapter: TransparencyLogAdapter,
        tsa_adapter: RFC3161TSAAdapter | None,
        key_registry: KeyRegistryAdapter,
        artifact_verifier: ArtifactVerifierPort,
        ots_adapter: OTSAdapter | None = None,
        env_path: Path | None = None,
    ) -> None:
        self._audit_store = audit_store
        self._transparency_log_adapter = transparency_log_adapter
        self._tsa_adapter = tsa_adapter
        self._key_registry = key_registry
        self._artifact_verifier = artifact_verifier
        self._ots_adapter = ots_adapter
        self._env_path = env_path or Path(".env")

    def audit_artifact(
        self,
        artifact_path: Path,
        tsa_ca_cert_path: Path | None,
        repository_path: Path | None = None,
    ) -> AuditReport:
        """Run full-chain audit and persist report."""
        if should_log_route("fine"):
            _logger.info(
                "audit_artifact path=%s",
                str(artifact_path)[:100] + "..."
                if len(str(artifact_path)) > 100
                else str(artifact_path),
                extra=get_log_extra(),
            )

        request_id: str | None = None
        try:
            request_id = str(extract_request_id_from_artifact_path(artifact_path))
            bind_log_context(request_id=request_id)
        except RuntimeError:
            request_id = None

        branch: str | None = None
        commit_oid: str | None = None
        ledger_path: str | None = None
        if request_id and repository_path is not None:
            branch, commit_oid, ledger_path = self._resolve_branch_context(
                repository_path, request_id
            )

        try:
            envelope, payload = parse_artifact_markdown(artifact_path)
            digest_hex = compute_payload_hash(payload)
            if branch and commit_oid and ledger_path and repository_path is not None:
                log_text = self._read_optional_blob_from_branch(
                    repository_path, f"artifact/{request_id}", ".provenance/transparency-log.jsonl"
                )
                entries = self._transparency_log_adapter.parse_entries_from_jsonl(log_text)
                transparency_anchor_found = any(e.artifact_hash == digest_hex for e in entries)
                transparency_log_integrity = (
                    self._transparency_log_adapter.verify_integrity_entries(entries)
                )
            else:
                if repository_path is not None:
                    log_text = self._read_optional_blob_from_head(
                        repository_path,
                        ".provenance/transparency-log.jsonl",
                    )
                    entries = self._transparency_log_adapter.parse_entries_from_jsonl(log_text)
                else:
                    entries = self._transparency_log_adapter.find_entries_by_artifact_hash(
                        digest_hex
                    )
                transparency_anchor_found = any(e.artifact_hash == digest_hex for e in entries)
                transparency_log_integrity = (
                    self._transparency_log_adapter.verify_integrity_entries(entries)
                    if entries
                    else True
                )
            # v3: remote_anchor_verified removed (Supabase code gone, pre-release.md §1).
            # Bitcoin (OTS) is the only remote anchor.
            remote_anchor_verified: bool | None = None
            remote_error_message: str | None = None
            manifest_hash, manifest_bytes = self._read_manifest_for_file(artifact_path)
            ots_forged, bitcoin_block_height = self._verify_ots_from_git(
                repository_path=repository_path,
                request_id=request_id,
                branch=branch,
                payload=payload,
            )
            report = self._build_audit_report(
                envelope=envelope,
                payload=payload,
                request_id=request_id,
                source_file=str(artifact_path),
                manifest_hash=manifest_hash,
                manifest_bytes=manifest_bytes,
                transparency_anchor_found=transparency_anchor_found,
                transparency_log_integrity=transparency_log_integrity,
                remote_anchor_verified=remote_anchor_verified,
                remote_error_message=remote_error_message,
                tsa_ca_cert_path=tsa_ca_cert_path,
                branch=branch,
                commit_oid=commit_oid,
                ledger_path=ledger_path,
                ots_forged=ots_forged,
                bitcoin_block_height=bitcoin_block_height,
            )
        except (RuntimeError, KeyError, ValueError, FileNotFoundError, OSError) as exc:
            report = self._build_error_report(
                source_file=str(artifact_path),
                request_id=request_id,
                error_message=str(exc),
                branch=branch,
                ledger_path=ledger_path,
            )
        except Exception:
            _logger.exception("Unexpected error during audit_artifact")
            raise
        self._persist_report(report)
        return report

    @staticmethod
    def _resolve_branch_context(
        repository_path: Path,
        request_id: str,
    ) -> tuple[str | None, str | None, str | None]:
        """Resolve branch, commit_oid, ledger_path for artifact when branch exists."""
        branch = f"artifact/{request_id}"
        ref_name = f"refs/heads/{branch}"
        ledger_path = f"{request_id}.md"
        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
            commit_obj = repo[reference.target]
            if isinstance(commit_obj, pygit2.Commit):
                return branch, str(commit_obj.id), ledger_path
        except (KeyError, pygit2.GitError):
            pass
        return None, None, None

    @staticmethod
    def _read_optional_blob_from_branch(
        repository_path: Path,
        branch_name: str,
        relative_path: str,
    ) -> str:
        """Read blob from branch or return empty string if branch/path missing."""
        ref_name = f"refs/heads/{branch_name}"
        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
            commit_obj = repo[reference.target]
            if not isinstance(commit_obj, pygit2.Commit):
                return ""
            blob_obj = tree_get_blob(repo, commit_obj.tree, relative_path)
        except (KeyError, pygit2.GitError):
            return ""
        if blob_obj is None:
            return ""
        return bytes(blob_obj.data).decode("utf-8")

    @staticmethod
    def _read_blob_bytes_from_commit(
        repo: pygit2.Repository,
        commit_obj: pygit2.Commit,
        relative_path: str,
    ) -> bytes | None:
        """Read raw blob bytes from commit; return None if path missing."""
        blob_obj = tree_get_blob(repo, commit_obj.tree, relative_path)
        if blob_obj is None:
            return None
        return bytes(blob_obj.data)

    @staticmethod
    def _read_optional_blob_bytes_from_branch(
        repository_path: Path,
        branch_name: str,
        relative_path: str,
    ) -> bytes | None:
        """Read raw blob bytes from branch; return None if branch/path missing."""
        ref_name = f"refs/heads/{branch_name}"
        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
            commit_obj = repo[reference.target]
            if not isinstance(commit_obj, pygit2.Commit):
                return None
            return VerificationService._read_blob_bytes_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                relative_path=relative_path,
            )
        except (KeyError, pygit2.GitError):
            return None

    @staticmethod
    def _read_optional_blob_from_head(
        repository_path: Path,
        relative_path: str,
    ) -> str:
        """Read blob from HEAD commit; return empty string if path missing."""
        try:
            repo = pygit2.Repository(str(repository_path))
            commit_obj = repo.revparse_single("HEAD")
            if not isinstance(commit_obj, pygit2.Commit):
                return ""
            blob_obj = tree_get_blob(repo, commit_obj.tree, relative_path)
        except (KeyError, pygit2.GitError, AttributeError, ValueError):
            return ""
        if blob_obj is None:
            return ""
        return bytes(blob_obj.data).decode("utf-8")

    def _verify_webauthn(
        self,
        envelope: Artifact,
        payload: str,
    ) -> tuple[bool, str | None]:
        """Verify an operator WebAuthn assertion. v3 (Flaw A).

        Returns ``(verified, skip_reason)``. ``skip_reason`` is non-None when
        verification could not be attempted (e.g. no attestation on the artifact,
        no credential public key resolvable, RP ID not configured). This is the
        honest "captured-unverified" state — distinct from a real verification
        failure (which returns ``(False, None)``).

        The verifier resolves the credential public key from the local
        ``.webauthn-credentials.json`` (operator-state file). Cross-machine
        verification (e.g. a third-party verifier using the published registry)
        is the web-ui's job; this method serves the CLI audit path.
        """
        # v3 (Gap 2): webauthn lives on the sealer's OperatorSeal, not Provenance.
        sealer_seal = next(
            (s for s in envelope.operator_seals if s.role == "sealer"),
            envelope.operator_seals[0] if envelope.operator_seals else None,
        )
        wa = sealer_seal.webauthn_attestation if sealer_seal is not None else None
        if wa is None:
            return False, "no attestation captured"
        # clientDataJson is required for verification. Legacy v2 artifacts lack it.
        if not getattr(wa, "client_data_json", None):
            return False, "legacy v2 attestation (no clientDataJson — cannot verify)"

        rp_id = self._resolve_webauthn_rp_id()
        if rp_id is None:
            return False, "WEBAUTHN_RP_ID not configured"

        credential_cose = self._resolve_webauthn_credential_public_key(wa.credential_id)
        if credential_cose is None:
            return False, "credential public key not found in local store"

        from src.canonicalization import canonicalize_body_for_hash
        from src.webauthn_attestation import verify_webauthn_assertion

        challenge_hash = hashlib.sha256(canonicalize_body_for_hash(payload)).digest()
        ok = verify_webauthn_assertion(
            wa,
            expected_rp_id=rp_id,
            expected_challenge_hash=challenge_hash,
            credential_public_key_cose=credential_cose,
        )
        return ok, (None if ok else "signature/RP/challenge check failed")

    def _resolve_webauthn_rp_id(self) -> str | None:
        """Resolve the RP ID for WebAuthn verification."""
        try:
            from src.webauthn_attestation import _resolve_rp_id

            return _resolve_rp_id(env_path=self._env_path)
        except Exception:  # noqa: BLE001
            return None

    def _resolve_webauthn_credential_public_key(self, credential_id: str) -> bytes | None:
        """Resolve the stored COSE public key for a credential id.

        Reads from the operator-state credentials file (the same one written at
        enrollment). This serves the *local* CLI audit; cross-machine verifiers
        use the published registry instead.
        """
        try:
            import base64

            from src.webauthn_attestation import _get_credentials_path, _load_credentials

            path = _get_credentials_path(env_path=self._env_path)
            stored = _load_credentials(path)
            stored_id = stored.get("credential_id", "")
            # base64url compare (padding-insensitive)
            padded = stored_id + "=" * (-len(stored_id) % 4)
            if padded != credential_id + "=" * (-len(credential_id) % 4):
                return None
            pub_b64 = stored.get("public_key_cose_b64")
            if not pub_b64:
                return None
            return base64.urlsafe_b64decode(pub_b64 + "=" * (-len(pub_b64) % 4))
        except Exception:  # noqa: BLE001
            return None

    def _verify_remote_anchor(
        self,
        digest_hex: str,  # noqa: ARG002
        entries: list[TransparencyLogEntry],  # noqa: ARG002
    ) -> bool | None:
        """v3 stub. Remote Supabase verification was removed (pre-release.md §1).

        Always returns None (= "skip"). Bitcoin (OTS) is the only remote trust
        root. The method is retained so legacy callers/tests that invoke it
        don't break; the parameter plumbing in audit_artifact /
        audit_committed_artifact is preserved as dead-but-harmless.
        """
        return None

    def audit_committed_artifact(
        self,
        repository_path: Path,
        request_id: UUID,
        tsa_ca_cert_path: Path | None,
    ) -> AuditReport:
        """Audit one artifact branch directly from git objects."""
        bind_log_context(request_id=request_id)
        if should_log_route("fine"):
            _logger.info(
                "audit_committed_artifact request_id=%s",
                request_id,
                extra=get_log_extra(),
            )

        branch = f"artifact/{request_id}"
        ref_name = f"refs/heads/{branch}"
        ledger_path = f"{request_id}.md"
        try:
            repo = pygit2.Repository(str(repository_path))
            reference = repo.lookup_reference(ref_name)
            commit_obj = repo[reference.target]
            if not isinstance(commit_obj, pygit2.Commit):
                raise RuntimeError(f"Branch ref '{ref_name}' does not point to a commit.")
            ledger_path = self._resolve_ledger_path_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                request_id=str(request_id),
            )
            markdown_text = self._read_blob_text_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                relative_path=ledger_path,
            )
            envelope, payload = parse_artifact_markdown_text(markdown_text)
            digest_hex = compute_payload_hash(payload)
            log_text = self._read_optional_blob_text_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                relative_path=".provenance/transparency-log.jsonl",
            )
            entries = self._transparency_log_adapter.parse_entries_from_jsonl(log_text)
            transparency_anchor_found = any(entry.artifact_hash == digest_hex for entry in entries)
            transparency_log_integrity = self._transparency_log_adapter.verify_integrity_entries(
                entries
            )
            remote_anchor_verified: bool | None = None
            remote_error_message: str | None = None
            try:
                remote_anchor_verified = self._verify_remote_anchor(
                    digest_hex=digest_hex,
                    entries=entries,
                )
            except RuntimeError as remote_exc:
                remote_anchor_verified = False
                remote_error_message = str(remote_exc)
            manifest_hash, manifest_bytes = self._read_manifest_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                ledger_path=ledger_path,
            )
            ots_forged, bitcoin_block_height = self._verify_ots_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                request_id=str(request_id),
                payload=payload,
            )
            catalog_errors = self._catalog_source_errors(
                repository_path=repository_path,
                request_id=str(request_id),
                envelope_source=envelope.provenance.source,
            )
            superseded_by = self._resolve_catalog_superseded_by(
                repository_path=repository_path,
                request_id=str(request_id),
            )
            sidecars = parse_sidecars_from_markdown(markdown_text)
            unattended_ceremony = envelope.provenance.provenance_grade == "unattended" or (
                envelope.provenance.author_attestation is not None
                and envelope.provenance.author_attestation.attestation_mode == "unattended"
            )
            # v3 (Gap 2): webauthn presence comes from the sealer's OperatorSeal.
            sealer_seal = next(
                (s for s in envelope.operator_seals if s.role == "sealer"),
                envelope.operator_seals[0] if envelope.operator_seals else None,
            )
            webauthn_present = (
                sealer_seal is not None and sealer_seal.webauthn_attestation is not None
            )
            webauthn_verified, webauthn_skip_reason = self._verify_webauthn(
                envelope=envelope,
                payload=payload,
            )
            ots_sidecar_declared = sidecars.ots is not None
            ots_blob_present = (
                sidecars.ots is not None
                and tree_get_blob(repo, commit_obj.tree, sidecars.ots) is not None
            )
            report = self._build_audit_report(
                envelope=envelope,
                payload=payload,
                request_id=str(request_id),
                source_file=ledger_path,
                manifest_hash=manifest_hash,
                manifest_bytes=manifest_bytes,
                transparency_anchor_found=transparency_anchor_found,
                transparency_log_integrity=transparency_log_integrity,
                remote_anchor_verified=remote_anchor_verified,
                remote_error_message=remote_error_message,
                tsa_ca_cert_path=tsa_ca_cert_path,
                branch=branch,
                commit_oid=str(commit_obj.id),
                ledger_path=ledger_path,
                ots_forged=ots_forged,
                bitcoin_block_height=bitcoin_block_height,
                extra_errors=catalog_errors,
                unattended_ceremony=unattended_ceremony,
                webauthn_present=webauthn_present,
                webauthn_verified=webauthn_verified,
                webauthn_verify_skipped=webauthn_skip_reason,
                superseded_by=superseded_by,
                ots_sidecar_declared=ots_sidecar_declared,
                ots_blob_present=ots_blob_present,
            )
        except (RuntimeError, KeyError, ValueError, FileNotFoundError, OSError) as exc:
            report = self._build_error_report(
                source_file=ledger_path,
                request_id=str(request_id),
                error_message=str(exc),
                branch=branch,
                ledger_path=ledger_path,
            )
        except Exception:
            _logger.exception("Unexpected error during audit_committed_artifact")
            raise
        self._persist_report(report)
        return report

    def _verify_ots_from_git(
        self,
        repository_path: Path | None,
        request_id: str | None,
        branch: str | None,
        payload: str,
    ) -> tuple[bool, int | None]:
        """Verify OTS proof from Git; return (ots_forged, bitcoin_block_height)."""
        if not request_id or not repository_path or not self._ots_adapter:
            return False, None
        branch_name = branch or f"artifact/{request_id}"
        ots_path = f".provenance/ots-{request_id}.ots"
        ots_bytes = self._read_optional_blob_bytes_from_branch(
            repository_path, branch_name, ots_path
        )
        if not ots_bytes:
            return False, None
        return self._ots_adapter.verify_ots_proof(
            payload_bytes=canonicalize_body_for_hash(payload),
            ots_bytes=ots_bytes,
        )

    def _verify_ots_from_commit(
        self,
        repo: pygit2.Repository,
        commit_obj: pygit2.Commit,
        request_id: str,
        payload: str,
    ) -> tuple[bool, int | None]:
        """Verify OTS proof from commit; return (ots_forged, bitcoin_block_height)."""
        if not self._ots_adapter:
            return False, None
        ots_path = f".provenance/ots-{request_id}.ots"
        ots_bytes = self._read_blob_bytes_from_commit(
            repo=repo, commit_obj=commit_obj, relative_path=ots_path
        )
        if not ots_bytes:
            return False, None
        return self._ots_adapter.verify_ots_proof(
            payload_bytes=canonicalize_body_for_hash(payload),
            ots_bytes=ots_bytes,
        )

    def _catalog_source_errors(
        self,
        repository_path: Path,
        request_id: str,
        envelope_source: str,
    ) -> list[str]:
        """Return errors when catalog row source disagrees with envelope claim."""

        try:
            adapter = CatalogAdapter(
                repository_path=repository_path,
                env_path=self._env_path,
            )
            row = next(
                (
                    entry
                    for entry in adapter.read_entries()
                    if str(entry.get("requestId")) == request_id
                ),
                None,
            )
        except (RuntimeError, OSError, KeyError):
            return []
        if row is None:
            return []
        catalog_source = row.get("source")
        if catalog_source != envelope_source:
            return [f"Catalog source '{catalog_source}' != envelope source '{envelope_source}'."]
        return []

    def _resolve_catalog_superseded_by(
        self,
        repository_path: Path,
        request_id: str,
    ) -> str | None:
        """Look up this artifact's catalog row and return its supersededBy, if any.

        v3 (Gap 1): a superseded artifact is honest — it just has a newer version.
        Surfaced as WARN, not FAIL.
        """
        try:
            adapter = CatalogAdapter(
                repository_path=repository_path,
                env_path=self._env_path,
            )
            row = next(
                (
                    entry
                    for entry in adapter.read_entries()
                    if str(entry.get("requestId")) == request_id
                ),
                None,
            )
        except (RuntimeError, OSError, KeyError):
            return None
        if row is None:
            return None
        superseded_by = row.get("supersededBy")
        if isinstance(superseded_by, str) and superseded_by:
            return superseded_by
        return None

    def _build_audit_report(
        self,
        envelope: Artifact,
        payload: str,
        request_id: str | None,
        source_file: str,
        manifest_hash: str | None,
        manifest_bytes: bytes | None,
        transparency_anchor_found: bool,
        transparency_log_integrity: bool,
        remote_anchor_verified: bool | None = None,
        remote_error_message: str | None = None,
        tsa_ca_cert_path: Path | None = None,
        branch: str | None = None,
        commit_oid: str | None = None,
        ledger_path: str | None = None,
        ots_forged: bool = False,
        bitcoin_block_height: int | None = None,
        extra_errors: list[str] | None = None,
        unattended_ceremony: bool = False,
        webauthn_present: bool = False,
        webauthn_verified: bool = False,
        webauthn_verify_skipped: str | None = None,
        superseded_by: str | None = None,
        ots_sidecar_declared: bool = False,
        ots_blob_present: bool = False,
    ) -> AuditReport:
        errors: list[str] = list(extra_errors or [])
        signature_valid = False
        payload_hash_match = False
        timestamp_found = False
        timestamp_valid = False
        key_status = "unknown"
        c2pa_present = manifest_hash is not None and manifest_bytes is not None
        c2pa_valid = False
        c2pa_validation_state: str | None = None
        c2pa_errors: list[str] = []

        digest_hex = compute_payload_hash(payload)
        if envelope.signature is None:
            errors.append("Artifact envelope is missing signature block.")
        else:
            payload_hash_match = digest_hex == envelope.signature.artifact_hash
            if not payload_hash_match:
                errors.append("Payload hash mismatch against signature artifactHash.")
            key_status_lookup = self._key_registry.get_status(
                envelope.signature.verification_anchor.signer_fingerprint
            )
            key_status = key_status_lookup or "unregistered"

        signature_valid = self._artifact_verifier.verify_artifact_payload(
            envelope=envelope,
            payload=payload,
            manifest_hash=manifest_hash,
        )
        if c2pa_present and manifest_bytes is not None:
            validation_payload, validation_format = build_c2pa_validation_payload(
                envelope=envelope,
                body=payload,
                env_path=self._env_path,
            )
            c2pa_validation = validate_c2pa_sidecar(
                payload_bytes=validation_payload,
                manifest_bytes=manifest_bytes,
                content_type=envelope.content_type,
                payload_format=validation_format,
                env_path=self._env_path,
                body_for_mvp=payload,
            )
            c2pa_valid = c2pa_validation.valid
            c2pa_validation_state = c2pa_validation.validation_state
            c2pa_errors = c2pa_validation.errors
            if not c2pa_valid:
                errors.append("C2PA sidecar semantic validation failed.")
        if not transparency_anchor_found:
            errors.append("No transparency anchor found for artifact hash.")
        if not transparency_log_integrity:
            errors.append("Transparency log hash chain integrity check failed.")
        if remote_anchor_verified is False:
            if remote_error_message:
                errors.append(f"Remote transparency log: {remote_error_message}")
            else:
                errors.append("Remote transparency log: no matching entry.")
        if key_status == "revoked":
            errors.append("Signing key has been revoked.")

        token_base64_to_verify = (
            envelope.signature.rfc3161_token
            if (envelope.signature is not None and envelope.signature.rfc3161_token is not None)
            else None
        )

        if token_base64_to_verify is not None and self._tsa_adapter is not None:
            timestamp_found = True
            try:
                token_condensed = "".join(token_base64_to_verify.split())
                token_bytes = base64.b64decode(token_condensed.encode("ascii"), validate=True)
                verification = self._tsa_adapter.verify_timestamp_token(
                    digest_hex=digest_hex,
                    token_bytes=token_bytes,
                    tsa_ca_cert_path=tsa_ca_cert_path,
                    digest_algorithm="sha256",
                )
                timestamp_valid = verification.ok
                if not verification.ok:
                    errors.append(verification.message)
            except Exception as exc:
                timestamp_valid = False
                errors.append(f"Git timestamp verification failed: {exc}")
        else:
            if token_base64_to_verify is None:
                errors.append("No RFC3161 timestamp token.")

        return AuditReport(
            artifact_id=str(envelope.id),
            request_id=request_id,
            source_file=source_file,
            envelope_valid=not bool(extra_errors),
            signature_valid=signature_valid,
            payload_hash_match=payload_hash_match,
            transparency_anchor_found=transparency_anchor_found,
            transparency_log_integrity=transparency_log_integrity,
            remote_anchor_verified=remote_anchor_verified,
            timestamp_found=timestamp_found,
            timestamp_valid=timestamp_valid,
            key_status_at_signing_time=key_status,
            c2pa_present=c2pa_present,
            c2pa_valid=c2pa_valid,
            c2pa_validation_state=c2pa_validation_state,
            c2pa_errors=c2pa_errors,
            errors=errors,
            branch=branch,
            commit_oid=commit_oid,
            ledger_path=ledger_path,
            ots_forged=ots_forged,
            bitcoin_block_height=bitcoin_block_height,
            unattended_ceremony=unattended_ceremony,
            webauthn_present=webauthn_present,
            webauthn_verified=webauthn_verified,
            webauthn_verify_skipped=webauthn_verify_skipped,
            superseded_by=superseded_by,
            ots_sidecar_declared=ots_sidecar_declared,
            ots_blob_present=ots_blob_present,
        )

    def _build_error_report(
        self,
        source_file: str,
        request_id: str | None,
        error_message: str,
        branch: str | None = None,
        ledger_path: str | None = None,
    ) -> AuditReport:
        return AuditReport(
            artifact_id="",
            request_id=request_id,
            source_file=source_file,
            envelope_valid=False,
            signature_valid=False,
            payload_hash_match=False,
            transparency_anchor_found=False,
            transparency_log_integrity=False,
            remote_anchor_verified=None,
            timestamp_found=False,
            timestamp_valid=False,
            key_status_at_signing_time="unknown",
            c2pa_present=False,
            c2pa_valid=False,
            c2pa_validation_state=None,
            c2pa_errors=[],
            errors=[error_message],
            branch=branch,
            commit_oid=None,
            ledger_path=ledger_path,
            ots_forged=False,
            bitcoin_block_height=None,
        )

    def _persist_report(self, report: AuditReport) -> None:
        self._audit_store.create_audit_report(
            artifact_id=report.artifact_id or "<unknown>",
            request_id=report.request_id,
            report_json=json.dumps(report.to_dict(), sort_keys=True),
        )

    @staticmethod
    def _resolve_ledger_path_from_commit(
        repo: pygit2.Repository,
        commit_obj: pygit2.Commit,
        request_id: str,
    ) -> str:
        """Resolve ledger path by trying common layouts (flat, artifacts_directory)."""
        candidates = [f"{request_id}.md", f"artifact/{request_id}.md"]
        for candidate in candidates:
            if tree_get_blob(repo, commit_obj.tree, candidate) is not None:
                return candidate
        return f"{request_id}.md"

    @staticmethod
    def _read_manifest_for_file(artifact_path: Path) -> tuple[str | None, bytes | None]:
        sidecar_path = artifact_path.with_suffix(".c2pa")
        if not sidecar_path.exists():
            return (None, None)
        manifest_bytes = sidecar_path.read_bytes()
        return (sha256_hex(manifest_bytes), manifest_bytes)

    @staticmethod
    def _read_blob_text_from_commit(
        repo: pygit2.Repository,
        commit_obj: pygit2.Commit,
        relative_path: str,
    ) -> str:
        blob_obj = tree_get_blob(repo, commit_obj.tree, relative_path)
        if blob_obj is None:
            raise RuntimeError(f"Branch artifact path '{relative_path}' not found in commit.")
        return bytes(blob_obj.data).decode("utf-8")

    @staticmethod
    def _read_optional_blob_text_from_commit(
        repo: pygit2.Repository,
        commit_obj: pygit2.Commit,
        relative_path: str,
    ) -> str:
        try:
            return VerificationService._read_blob_text_from_commit(
                repo=repo,
                commit_obj=commit_obj,
                relative_path=relative_path,
            )
        except RuntimeError:
            return ""

    @staticmethod
    def _read_manifest_from_commit(
        repo: pygit2.Repository,
        commit_obj: pygit2.Commit,
        ledger_path: str,
    ) -> tuple[str | None, bytes | None]:
        sidecar_path = str(Path(ledger_path).with_suffix(".c2pa"))
        blob_obj = tree_get_blob(repo, commit_obj.tree, sidecar_path)
        if blob_obj is None:
            return (None, None)
        manifest_bytes = bytes(blob_obj.data)
        return (sha256_hex(manifest_bytes), manifest_bytes)
