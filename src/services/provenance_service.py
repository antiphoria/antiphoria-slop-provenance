"""Core provenance service for anchoring and trusted timestamping."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter, TimestampVerification
from src.adapters.transparency_log import TransparencyLogAdapter
from src.models import sha256_hex
from src.parsing import parse_artifact_markdown
from src.repository import SQLiteRepository


@dataclass(frozen=True)
class AnchorOutcome:
    """Transparency anchoring outcome payload."""

    entry_id: str
    entry_hash: str
    artifact_hash: str
    artifact_id: str
    anchored_at: str
    log_path: str


@dataclass(frozen=True)
class TimestampOutcome:
    """Timestamping outcome payload."""

    created_at: str
    tsa_url: str
    digest_algorithm: str
    verification: TimestampVerification


class ProvenanceService:
    """Coordinates provenance anchoring, timestamping, and key registration."""

    def __init__(
        self,
        repository: SQLiteRepository,
        transparency_log_adapter: TransparencyLogAdapter,
        tsa_adapter: RFC3161TSAAdapter | None,
        key_registry: KeyRegistryAdapter,
    ) -> None:
        self._repository = repository
        self._transparency_log_adapter = transparency_log_adapter
        self._tsa_adapter = tsa_adapter
        self._key_registry = key_registry

    def register_signing_key(
        self,
        signer_fingerprint: str,
        key_version: str | None,
    ) -> None:
        """Register signing key metadata in the local key registry."""

        metadata = json.dumps({"managedBy": "slop-orchestrator"})
        self._key_registry.register_key(
            fingerprint=signer_fingerprint,
            key_version=key_version,
            status="active",
            metadata_json=metadata,
        )

    def anchor_artifact(
        self,
        artifact_path: Path,
        request_id: UUID | None,
    ) -> AnchorOutcome:
        """Anchor one artifact hash in append-only transparency log."""

        envelope, payload = parse_artifact_markdown(artifact_path)
        artifact_hash = sha256_hex(payload.encode("utf-8"))
        if envelope.signature is None:
            raise RuntimeError("Artifact envelope is missing signature block.")
        if artifact_hash != envelope.signature.artifact_hash:
            raise RuntimeError("Artifact hash mismatch for transparency anchor request.")

        entry = self._transparency_log_adapter.append_entry(
            artifact_hash=artifact_hash,
            artifact_id=str(envelope.id),
            source_file=artifact_path,
            request_id=None if request_id is None else str(request_id),
            metadata={"source": envelope.provenance.source},
        )
        self._repository.create_transparency_log_record(
            entry_id=entry.entry_id,
            artifact_hash=entry.artifact_hash,
            artifact_id=entry.artifact_id,
            request_id=entry.request_id,
            source_file=entry.source_file,
            log_path=str(self._transparency_log_adapter.log_path),
            previous_entry_hash=entry.previous_entry_hash,
            entry_hash=entry.entry_hash,
            published_at=entry.anchored_at,
            remote_receipt=entry.remote_receipt,
        )
        return AnchorOutcome(
            entry_id=entry.entry_id,
            entry_hash=entry.entry_hash,
            artifact_hash=entry.artifact_hash,
            artifact_id=entry.artifact_id,
            anchored_at=entry.anchored_at,
            log_path=str(self._transparency_log_adapter.log_path),
        )

    def timestamp_artifact(
        self,
        artifact_path: Path,
        request_id: UUID | None,
        tsa_ca_cert_path: Path | None,
        digest_algorithm: str = "sha256",
    ) -> TimestampOutcome:
        """Acquire and verify RFC3161 token for one artifact hash."""

        if self._tsa_adapter is None:
            raise RuntimeError("TSA adapter is not configured.")
        envelope, payload = parse_artifact_markdown(artifact_path)
        artifact_hash = sha256_hex(payload.encode("utf-8"))
        token_bytes = self._tsa_adapter.request_timestamp_token(
            digest_hex=artifact_hash,
            digest_algorithm=digest_algorithm,
        )
        verification = self._tsa_adapter.verify_timestamp_token(
            digest_hex=artifact_hash,
            token_bytes=token_bytes,
            tsa_ca_cert_path=tsa_ca_cert_path,
            digest_algorithm=digest_algorithm,
        )
        encoded_token = base64.b64encode(token_bytes).decode("ascii")
        created_at = self._repository.create_timestamp_record(
            artifact_hash=artifact_hash,
            artifact_id=str(envelope.id),
            request_id=None if request_id is None else str(request_id),
            tsa_url=self._tsa_adapter.tsa_url or "",
            token_base64=encoded_token,
            digest_algorithm=digest_algorithm,
            verification_status="verified" if verification.ok else "failed",
            verification_message=verification.message,
        )
        return TimestampOutcome(
            created_at=created_at,
            tsa_url=self._tsa_adapter.tsa_url or "",
            digest_algorithm=digest_algorithm,
            verification=verification,
        )
