"""Minimal C2PA-compatible sidecar manifest generator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone

from src.models import Artifact, canonical_json_bytes, sha256_hex


@dataclass(frozen=True)
class C2PAManifestArtifact:
    """Generated C2PA sidecar payload and canonical hash."""

    manifest_bytes: bytes
    manifest_hash: str


def build_c2pa_sidecar_manifest(envelope: Artifact, body: str) -> C2PAManifestArtifact:
    """Build deterministic C2PA-style sidecar payload from artifact envelope."""

    payload_hash = sha256_hex(body.encode("utf-8"))
    payload = {
        "c2paVersion": "2.3",
        "claimGenerator": envelope.provenance.engine_version,
        "title": envelope.title,
        "assertions": {
            "c2pa.actions": [
                {
                    "action": "c2pa.created",
                    "digitalSourceType": (
                        "http://cv.iptc.org/newscodes/digitalsourcetype/"
                        "trainedAlgorithmicMedia"
                    ),
                    "when": envelope.timestamp.astimezone(timezone.utc).isoformat(),
                }
            ],
            "c2pa.asset": {
                "artifactId": str(envelope.id),
                "contentType": envelope.content_type,
                "payloadHash": payload_hash,
            },
            "slopOrchestrator.context": {
                "schemaVersion": envelope.schema_version,
                "source": envelope.provenance.source,
                "modelId": envelope.provenance.model_id,
                "generatedAt": envelope.timestamp.isoformat(),
            },
        },
    }
    manifest_bytes = canonical_json_bytes(payload)
    return C2PAManifestArtifact(
        manifest_bytes=manifest_bytes,
        manifest_hash=sha256_hex(manifest_bytes),
    )
