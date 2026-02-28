"""Policy primitives for content provenance class and licensing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ProvenanceClass = Literal["human", "hybrid", "synthetic"]


@dataclass(frozen=True)
class ContentLicensePolicy:
    """License policy assigned to one provenance class."""

    provenance_class: ProvenanceClass
    license_id: str
    attribution_required: bool
    description: str


DEFAULT_CONTENT_POLICIES: tuple[ContentLicensePolicy, ...] = (
    ContentLicensePolicy(
        provenance_class="human",
        license_id="ARR",
        attribution_required=False,
        description="Human-authored works default to all rights reserved.",
    ),
    ContentLicensePolicy(
        provenance_class="hybrid",
        license_id="CC-BY-4.0",
        attribution_required=True,
        description="Hybrid works require source and model attribution.",
    ),
    ContentLicensePolicy(
        provenance_class="synthetic",
        license_id="CC0-1.0",
        attribution_required=False,
        description="Fully synthetic outputs default to CC0 dedication.",
    ),
)
