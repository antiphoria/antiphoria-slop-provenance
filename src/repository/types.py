"""Repository datatypes and shared lifecycle status aliases."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

ArtifactLifecycleStatus = Literal[
    "requested",
    "generated",
    "signed",
    "curated",
    "committed",
    "failed",
]

OtsForgeStatus = Literal["PENDING", "FORGED", "FAILED"]


@dataclass(frozen=True)
class OtsForgeRecord:
    """OpenTimestamps forge state for one artifact."""

    request_id: str
    artifact_hash: str
    status: str
    pending_ots_b64: str
    final_ots_b64: str | None
    bitcoin_block_height: int | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class ArtifactRecord:
    """Persistent lifecycle state for one artifact pipeline request."""

    request_id: str
    status: ArtifactLifecycleStatus
    title: str
    prompt: str
    body: str
    model_id: str
    artifact_hash: str
    cryptographic_signature: str
    ledger_path: str | None
    commit_oid: str | None
    created_at: str
    updated_at: str


def utc_now_iso() -> str:
    """Return current UTC timestamp as ISO-8601 string."""

    return datetime.now(timezone.utc).isoformat()
