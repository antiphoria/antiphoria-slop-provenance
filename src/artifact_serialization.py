"""YAML helpers shared by the v3 envelope codec.

v3 (pre-release.md §1): the v1 wire renderer that used to live here
(``render_artifact_markdown``) was removed — v3 always emits the antiphoria
enterprise layout via ``envelope_v2.render_artifact_markdown_v2``. The helpers
below remain because the v3 codec imports them.
"""

from __future__ import annotations

import textwrap


def _wrap_signature_lines(signature_base64: str, line_width: int = 76) -> list[str]:
    """Wrap a base64 string into fixed-width lines for YAML literal blocks."""

    return textwrap.wrap(signature_base64, line_width) or [""]


def _yaml_quoted(value: str) -> str:
    """Quote a string for YAML. Doubles backslashes and quotes inside."""

    if value is None:
        return '""'
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _yaml_literal_block(text: str, indent: int) -> str:
    """Render a string as a YAML literal block (``|-``) at the given indent."""

    if text is None:
        text = ""
    indent_str = " " * indent
    lines = text.splitlines() or [""]
    return "\n".join(f"{indent_str}{line}" for line in lines)
