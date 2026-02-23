"""Canonical artifact contracts for Astro-compatible publication.

This module defines strict Pydantic models for the artifact frontmatter
specified in `.cursorrules`. Field aliases intentionally preserve the exact
Astro/YAML key names expected by downstream publishing adapters.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CRYPTO_ALGORITHM_ML_DSA_44 = "CRYSTALS-Dilithium (NIST ML-DSA-44)"
"""Canonical algorithm label required in frontmatter."""


class Provenance(BaseModel):
    """Immutable provenance metadata for a generated artifact.

    Attributes:
        source: Origin marker for the artifact payload.
        prompt: User prompt that initiated generation.
        model_id: Generator model identifier (serialized as `modelId`).
        artifact_hash: SHA-256 hash (serialized as `artifactHash`).
        crypto_algorithm: Signature algorithm label serialized as
            `cryptoAlgorithm`.
        cryptographic_signature: Base64 post-quantum signature serialized as
            `cryptographicSignature`. This may include newline breaks.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    source: Literal["synthetic", "hybrid"] = "synthetic"
    prompt: str = Field(min_length=1)
    model_id: str = Field(alias="modelId", min_length=1)
    artifact_hash: str = Field(
        alias="artifactHash",
        min_length=64,
        max_length=64,
        pattern=r"^[a-fA-F0-9]{64}$",
    )
    crypto_algorithm: Literal[CRYPTO_ALGORITHM_ML_DSA_44] = Field(
        alias="cryptoAlgorithm",
        default=CRYPTO_ALGORITHM_ML_DSA_44,
    )
    cryptographic_signature: str = Field(alias="cryptographicSignature", min_length=1)


class Curation(BaseModel):
    """Human curation metadata for hybrid artifacts.

    Attributes:
        difference_score: Percentage of changed text serialized as
            `differenceScore`.
        unified_diff: Unified patch diff serialized as `unifiedDiff`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    difference_score: float = Field(alias="differenceScore", ge=0.0)
    unified_diff: str = Field(alias="unifiedDiff", min_length=1)


class Artifact(BaseModel):
    """Strict frontmatter schema for Astro artifact records.

    Attributes:
        title: Human-readable record title for frontmatter.
        provenance: Cryptographic and generation provenance metadata.
        curation: Optional curation metadata for hybrid artifacts.
        record_status: Verification status serialized as `recordStatus`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    title: str = Field(min_length=1)
    provenance: Provenance
    curation: Curation | None = None
    record_status: Literal["unverified"] = Field(
        alias="recordStatus",
        default="unverified",
    )

    def to_frontmatter_dict(self) -> dict[str, object]:
        """Return a frontmatter-safe dictionary using exact output keys.

        Returns:
            A dictionary with aliases (`modelId`, `artifactHash`,
            `cryptoAlgorithm`, `cryptographicSignature`, `recordStatus`) for
            direct YAML serialization.
        """

        return self.model_dump(by_alias=True)
