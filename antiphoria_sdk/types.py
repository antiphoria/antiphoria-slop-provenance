"""Public types for antiphoria_sdk. Pydantic v2, frozen, strict."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StepType:
    """Well-known step type strings. Factories may introduce additional
    values as long as they match the validation pattern in ChainRecord
    (SCREAMING_SNAKE_CASE, ASCII, up to 64 chars).
    """

    GENESIS = "GENESIS"
    PRE_GENERATOR = "PRE_GENERATOR"
    POST_GENERATOR = "POST_GENERATOR"
    PRE_VERIFIER = "PRE_VERIFIER"
    POST_VERIFIER = "POST_VERIFIER"
    PRE_REVISER = "PRE_REVISER"
    POST_REVISER = "POST_REVISER"
    PRE_FINALIZE = "PRE_FINALIZE"
    POST_FINALIZE = "POST_FINALIZE"
    MANIFEST = "MANIFEST"


_STEP_TYPE_PATTERN = r"^[A-Z][A-Z0-9_]{0,63}$"
_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
_SHA256_RE = re.compile(_SHA256_PATTERN)


def is_safe_relative_path(rel: str) -> bool:
    """Return True when ``rel`` is a safe POSIX-style relative path.

    Rules:
        * Non-empty, no leading ``/``, no Windows drive letter (``C:``).
        * No backslashes (POSIX-only for cross-platform stability).
        * No empty segments (``//``), no ``.`` or ``..`` segments.
    """
    if not rel or rel.startswith("/"):
        return False
    if len(rel) >= 2 and rel[1] == ":":
        return False
    if "\\" in rel:
        return False
    parts = rel.split("/")
    return all(part and part not in (".", "..") for part in parts)


class Signature(BaseModel):
    """Hybrid signature: ML-DSA-44 (post-quantum) + Ed25519 (classical).

    Both MUST verify for a signature to be considered valid.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: str = Field(pattern=r"^ml-dsa-44\+ed25519$")
    mldsa_signature_b64: str = Field(min_length=1)
    ed25519_signature_b64: str = Field(min_length=1)
    public_key_fingerprint: str = Field(min_length=16, max_length=64, pattern=r"^[0-9a-f]+$")


class ChainRecord(BaseModel):
    """Canonical on-disk format for one link in a seal chain.

    Byte-layout invariant: the file on disk equals
    `canonical_json_bytes(record.model_dump(mode='json'))`. This is
    enforced by `SealEngine` on write and re-checked on verify.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    sdk_version: str
    run_id: str = Field(min_length=1)
    step_index: int = Field(ge=0)
    step_type: str = Field(pattern=_STEP_TYPE_PATTERN)
    content_file_hashes: dict[str, str]
    metadata: dict[str, Any]
    previous_hash: str | None  # None only for GENESIS
    timestamp: str  # ISO-8601 UTC
    signature: Signature

    @field_validator("previous_hash")
    @classmethod
    def _validate_previous_hash(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _SHA256_RE.match(v):
            raise ValueError(f"previous_hash must match {_SHA256_PATTERN}: {v!r}")
        return v

    @field_validator("content_file_hashes")
    @classmethod
    def _validate_content_file_hashes(cls, v: dict[str, str]) -> dict[str, str]:
        for rel, digest in v.items():
            if not is_safe_relative_path(rel):
                raise ValueError(
                    f"content_file_hashes key is not a safe relative path: {rel!r}",
                )
            if not _SHA256_RE.match(digest):
                raise ValueError(
                    f"content_file_hashes[{rel!r}] must match {_SHA256_PATTERN}: {digest!r}",
                )
        return v


class SealReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_index: int = Field(ge=0)
    step_type: str = Field(pattern=_STEP_TYPE_PATTERN)
    entry_hash: str = Field(pattern=_SHA256_PATTERN)
    previous_hash: str | None
    record_path: Path
    timestamp: str


class GenesisReceipt(SealReceipt):
    """Receipt for the first record in a chain. step_type == 'GENESIS'."""


class StepVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_index: int
    step_type: str
    record_path: Path
    signature_valid: bool
    content_hashes_valid: bool
    previous_hash_matches: bool
    canonical_form_valid: bool
    errors: list[str] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (
            self.signature_valid
            and self.content_hashes_valid
            and self.previous_hash_matches
            and self.canonical_form_valid
            and not self.errors
        )


class VerificationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    chain_intact: bool
    total_steps: int
    steps: list[StepVerification]
    first_error_index: int | None = None

    def summary(self) -> str:
        if self.chain_intact:
            return f"Chain intact: {self.total_steps} step(s) verified for run {self.run_id}."
        return (
            f"Chain BROKEN for run {self.run_id}: "
            f"first error at step {self.first_error_index} of {self.total_steps}."
        )
