"""Policy primitives for content provenance class and licensing."""

from __future__ import annotations

from typing import Literal

ProvenanceClass = Literal["human", "hybrid", "synthetic"]

DEFAULT_CONTENT_LICENSES: dict[ProvenanceClass, str] = {
    "human": "ARR",
    "hybrid": "CC-BY-4.0",
    "synthetic": "CC0-1.0",
}


def get_license_id(provenance_class: ProvenanceClass) -> str:
    """Return the default license_id for a provenance class."""
    return DEFAULT_CONTENT_LICENSES[provenance_class]
