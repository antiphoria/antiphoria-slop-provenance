"""Verification service for full-chain provenance audit reports."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from src.events import EventBus
from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter
from src.adapters.transparency_log import TransparencyLogAdapter
from src.models import sha256_hex
from src.repository import SQLiteRepository
from src.services.curation_service import extract_request_id_from_artifact_path
from src.services.provenance_service import parse_artifact_markdown


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
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert report dataclass to serializable dictionary."""

        return asdict(self)


class VerificationService:
    """Orchestrates envelope, signature, anchor, timestamp, and key checks."""

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

    def audit_artifact(
        self,
        artifact_path: Path,
        tsa_ca_cert_path: Path | None,
    ) -> AuditReport:
        """Run full-chain audit and persist report."""

        errors: list[str] = []
        envelope_valid = True
        signature_valid = False
        payload_hash_match = False
        transparency_anchor_found = False
        transparency_log_integrity = self._transparency_log_adapter.verify_integrity()
        timestamp_found = False
        timestamp_valid = False
        key_status = "unknown"
        request_id: str | None = None
        artifact_id = ""

        try:
            envelope, payload = parse_artifact_markdown(artifact_path)
            artifact_id = str(envelope.id)
            try:
                request_id = str(extract_request_id_from_artifact_path(artifact_path))
            except RuntimeError:
                request_id = None
            digest_hex = sha256_hex(payload.encode("utf-8"))
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
            signature_valid = CryptoNotaryAdapter(
                event_bus=EventBus(),
                require_private_key=False,
            ).verify_artifact(artifact_path)
            anchor_matches = self._transparency_log_adapter.find_entries_by_artifact_hash(
                digest_hex
            )
            transparency_anchor_found = len(anchor_matches) > 0
            if not transparency_anchor_found:
                errors.append("No transparency anchor found for artifact hash.")

            latest_timestamp = self._repository.get_latest_timestamp_record(digest_hex)
            if latest_timestamp is not None:
                timestamp_found = True
                if self._tsa_adapter is None:
                    timestamp_valid = False
                    errors.append("TSA adapter unavailable for RFC3161 verification.")
                else:
                    verification = self._repository.verify_latest_timestamp_record(
                        artifact_hash=digest_hex,
                        tsa_adapter=self._tsa_adapter,
                        tsa_ca_cert_path=tsa_ca_cert_path,
                    )
                    timestamp_valid = verification.ok
                    if not verification.ok:
                        errors.append(verification.message)
            else:
                errors.append("No RFC3161 timestamp token found for artifact hash.")
        except Exception as exc:  # noqa: BLE001
            envelope_valid = False
            errors.append(str(exc))

        report = AuditReport(
            artifact_id=artifact_id,
            request_id=request_id,
            source_file=str(artifact_path),
            envelope_valid=envelope_valid,
            signature_valid=signature_valid,
            payload_hash_match=payload_hash_match,
            transparency_anchor_found=transparency_anchor_found,
            transparency_log_integrity=transparency_log_integrity,
            timestamp_found=timestamp_found,
            timestamp_valid=timestamp_valid,
            key_status_at_signing_time=key_status,
            errors=errors,
        )
        self._repository.create_audit_report(
            artifact_id=artifact_id or "<unknown>",
            request_id=request_id,
            report_json=json.dumps(report.to_dict(), sort_keys=True),
        )
        return report
