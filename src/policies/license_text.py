"""Canonical license notice and statement text for eternity.v2 ``rights`` block."""

from __future__ import annotations

from dataclasses import dataclass

_PUBLISHER = "antiphoria"
_COPYRIGHT_YEAR = "2026"

_ARR_NOTICE = f"© {_COPYRIGHT_YEAR} {_PUBLISHER}. All Rights Reserved."
_ARR_STATEMENT = (
    f"Copyright © {_COPYRIGHT_YEAR} {_PUBLISHER}. All rights reserved. "
    "No license is granted to reproduce, distribute, publicly display, or create "
    f"derivative works from this text except as permitted by applicable law or with "
    f"prior written permission from {_PUBLISHER}."
)

_CC0_NOTICE = f"🅍 CC0 1.0 • Public Domain • {_PUBLISHER}"
_CC0_STATEMENT = (
    f"To the extent possible under law, {_PUBLISHER} has waived all copyright and "
    "related or neighboring rights to this work under the CC0 1.0 Universal "
    "(CC0 1.0) Public Domain Dedication."
)

_CC_BY_NOTICE = f"CC BY 4.0 • {_PUBLISHER}"
_CC_BY_STATEMENT = (
    "Licensed under Creative Commons Attribution 4.0 International (CC BY 4.0). "
    "Attribution required."
)


@dataclass(frozen=True)
class LicenseText:
    """Display and legal prose for one ``rights.policyId`` value."""

    notice: str
    statement: str


_LICENSE_TEXT: dict[str, LicenseText] = {
    "ARR": LicenseText(notice=_ARR_NOTICE, statement=_ARR_STATEMENT),
    "CC0-1.0": LicenseText(notice=_CC0_NOTICE, statement=_CC0_STATEMENT),
    "CC-BY-4.0": LicenseText(notice=_CC_BY_NOTICE, statement=_CC_BY_STATEMENT),
}


def resolve_license_text(policy_id: str) -> LicenseText:
    """Return canonical notice and statement for a policy id."""

    canonical = _LICENSE_TEXT.get(policy_id)
    if canonical is not None:
        return canonical
    return LicenseText(
        notice=f"Licensed under {policy_id}.",
        statement=f"Content licensed under policy {policy_id}.",
    )
