"""First-run acknowledgment: research and artistic use only.

Interactive users confirm once; automation sets env
ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK=1.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_ACK_ENV = "ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK"
_ACK_FILE_NAME = "research_artistic_use_ack_v1"
_ACK_SENTINEL = "antiphoria-slop-provenance-research-artistic-ack-v1"
_CONFIG_SUBDIR = "antiphoria-slop-provenance"


def _config_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / _CONFIG_SUBDIR
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / _CONFIG_SUBDIR
    return Path.home() / ".config" / _CONFIG_SUBDIR


def _ack_file_path() -> Path:
    return _config_dir() / _ACK_FILE_NAME


def is_research_use_acknowledged() -> bool:
    """True if env opt-out or prior interactive/file acknowledgment."""

    if os.environ.get(_ACK_ENV, "").strip() in {"1", "true", "yes"}:
        return True
    path = _ack_file_path()
    if not path.is_file():
        return False
    try:
        first = path.read_text(encoding="utf-8").splitlines()[:1]
        return bool(first) and first[0].strip() == _ACK_SENTINEL
    except OSError:
        return False


def write_research_use_acknowledgment() -> None:
    """Persist acknowledgment after user agrees interactively."""

    path = _ack_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat()
    path.write_text(f"{_ACK_SENTINEL}\n{stamp}\n", encoding="utf-8")


def argv_requests_help_only(argv: list[str]) -> bool:
    """True for top-level -h/--help or subcommand ... --help."""

    if not argv:
        return False
    if argv in (["-h"], ["--help"]):
        return True
    return len(argv) >= 2 and argv[-1] in ("-h", "--help")


_PROMPT_LINES = (
    "",
    "Use restriction:",
    ("  This software must be used in a research setting only and for artistic purposes."),
    ("  It is not a legal, regulatory, or commercial certification service."),
    "  See docs/TERMS_OF_USE.md and docs/DISCLAIMER.md in the repository.",
    "",
    "Type y (yes) to confirm and continue, or anything else to exit.",
)


def prompt_and_confirm_research_use() -> bool:
    """Print notice and read yes/no from stdin. Caller checks isatty first."""

    for line in _PROMPT_LINES:
        print(line, file=sys.stderr)
    try:
        reply = input("Confirm research / artistic use only [y/N]: ").strip().lower()
    except EOFError:
        return False
    return reply in {"y", "yes"}


def print_non_interactive_research_ack_hint() -> None:
    """Stderr hint when stdin is not a TTY and ack is missing."""

    msg = (
        "slop-cli: acknowledgment required. This software is for research "
        "and artistic use only. For non-interactive runs, set environment "
        f"variable {_ACK_ENV}=1 after reading docs/TERMS_OF_USE.md and "
        "docs/DISCLAIMER.md."
    )
    print(msg, file=sys.stderr)
