"""Canonical license notice and statement text for the v3 ``rights`` block.

Flaw F fix (pre-release.md §3): the rights block used to hardcode Antiphoria as
the copyright holder, which legally misattributes the author's work. The
templates now substitute ``{holder}`` — the author's declared pen name (or
legal name). Antiphoria warrants provenance; it does not own the work.

For backwards compatibility, ``resolve_license_text(policy_id, holder=None)``
falls back to the legacy Antiphoria-as-holder wording when no holder is given.
This keeps legacy v2 artifacts renderable; new v3 seals must always pass holder.
"""

from __future__ import annotations

from dataclasses import dataclass

_PUBLISHER = "antiphoria"
_COPYRIGHT_YEAR = "2026"

# v3 templates — author is the rights holder.
_ARR_NOTICE_V3 = "© {_COPYRIGHT_YEAR} {holder}. All Rights Reserved."
_ARR_STATEMENT_V3 = (
    "Copyright © {_COPYRIGHT_YEAR} {holder}. All rights reserved. "
    "No license is granted to reproduce, distribute, publicly display, or create "
    "derivative works from this text except as permitted by applicable law or with "
    "prior written permission from {holder}. Antiphoria warrants provenance only; "
    "it does not hold copyright in this work."
)

_CC0_NOTICE_V3 = "🅍 CC0 1.0 • Public Domain • {holder}"
_CC0_STATEMENT_V3 = (
    "To the extent possible under law, {holder} has waived all copyright and "
    "related or neighboring rights to this work under the CC0 1.0 Universal "
    "(CC0 1.0) Public Domain Dedication. Antiphoria warrants provenance only."
)

_CC_BY_NOTICE_V3 = "CC BY 4.0 • {holder}"
_CC_BY_STATEMENT_V3 = (
    "Copyright © {_COPYRIGHT_YEAR} {holder}. "
    "Licensed under Creative Commons Attribution 4.0 International (CC BY 4.0). "
    "Attribution required. Antiphoria warrants provenance only; "
    "it does not hold copyright in this work."
)

# Legacy v2 templates (Antiphoria as holder) — kept only so legacy artifacts
# remain renderable without migration. New v3 seals never use these.
_ARR_NOTICE_LEGACY = f"© {_COPYRIGHT_YEAR} {_PUBLISHER}. All Rights Reserved."
_ARR_STATEMENT_LEGACY = (
    f"Copyright © {_COPYRIGHT_YEAR} {_PUBLISHER}. All rights reserved. "
    "No license is granted to reproduce, distribute, publicly display, or create "
    f"derivative works from this text except as permitted by applicable law or with "
    f"prior written permission from {_PUBLISHER}."
)

_CC0_NOTICE_LEGACY = f"🅍 CC0 1.0 • Public Domain • {_PUBLISHER}"
_CC0_STATEMENT_LEGACY = (
    f"To the extent possible under law, {_PUBLISHER} has waived all copyright and "
    "related or neighboring rights to this work under the CC0 1.0 Universal "
    "(CC0 1.0) Public Domain Dedication."
)

_CC_BY_NOTICE_LEGACY = f"CC BY 4.0 • {_PUBLISHER}"
_CC_BY_STATEMENT_LEGACY = (
    "Licensed under Creative Commons Attribution 4.0 International (CC BY 4.0). "
    "Attribution required."
)


@dataclass(frozen=True)
class LicenseText:
    """Display and legal prose for one ``rights.policyId`` value."""

    notice: str
    statement: str


def _v3_text(policy_id: str, holder: str) -> LicenseText:
    """Build v3 license text with the author as rights holder."""
    fmt = {"holder": holder, "_COPYRIGHT_YEAR": _COPYRIGHT_YEAR}
    if policy_id == "ARR":
        return LicenseText(
            notice=_ARR_NOTICE_V3.format(**fmt),
            statement=_ARR_STATEMENT_V3.format(**fmt),
        )
    if policy_id == "CC0-1.0":
        return LicenseText(
            notice=_CC0_NOTICE_V3.format(**fmt),
            statement=_CC0_STATEMENT_V3.format(**fmt),
        )
    if policy_id == "CC-BY-4.0":
        return LicenseText(
            notice=_CC_BY_NOTICE_V3.format(**fmt),
            statement=_CC_BY_STATEMENT_V3.format(**fmt),
        )
    # Custom policy escape hatch — keep it generic but attribute to holder.
    return LicenseText(
        notice=f"© {_COPYRIGHT_YEAR} {holder}. Licensed under {policy_id}.",
        statement=(
            f"Copyright © {_COPYRIGHT_YEAR} {holder}. "
            f"Content licensed under policy {policy_id}. "
            "Antiphoria warrants provenance only; it does not hold copyright in this work."
        ),
    )


_LEGACY_TEXT: dict[str, LicenseText] = {
    "ARR": LicenseText(notice=_ARR_NOTICE_LEGACY, statement=_ARR_STATEMENT_LEGACY),
    "CC0-1.0": LicenseText(notice=_CC0_NOTICE_LEGACY, statement=_CC0_STATEMENT_LEGACY),
    "CC-BY-4.0": LicenseText(notice=_CC_BY_NOTICE_LEGACY, statement=_CC_BY_STATEMENT_LEGACY),
}


def resolve_license_text(policy_id: str, holder: str | None = None) -> LicenseText:
    """Return canonical notice and statement for a policy id.

    Args:
        policy_id: The license policy (ARR, CC0-1.0, CC-BY-4.0, or custom).
        holder: The rights holder (author pen name or legal name). Required for
            v3 seals — Antiphoria warrants provenance but does not own the work.
            If omitted, returns the legacy v2 wording (Antiphoria as holder) so
            legacy artifacts remain renderable without migration.
    """
    if holder is None or not holder.strip():
        # Legacy fallback — Antiphoria as holder. v3 seals must pass holder.
        canonical = _LEGACY_TEXT.get(policy_id)
        if canonical is not None:
            return canonical
        return LicenseText(
            notice=f"Licensed under {policy_id}.",
            statement=f"Content licensed under policy {policy_id}.",
        )
    return _v3_text(policy_id, holder.strip())
