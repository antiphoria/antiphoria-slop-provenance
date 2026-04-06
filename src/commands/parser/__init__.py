"""Composable parser entrypoint for CLI command groups."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path

from src.commands.parser.admin import register_admin_parsers
from src.commands.parser.maintenance import register_maintenance_parsers
from src.commands.parser.pipeline import register_pipeline_parsers
from src.commands.parser.verification import register_verification_parsers


def build_cli_parser(
    *,
    default_repo_path: Callable[[], str | None],
    read_env_optional: Callable[..., str | None],
    env_path: Path,
) -> argparse.ArgumentParser:
    """Build parser by composing parser registration modules."""
    cli_epilog = (
        "Research and artistic use only; not legal/regulatory certification. "
        "Terms: docs/TERMS_OF_USE.md, docs/DISCLAIMER.md. "
        "First run: confirm interactively or set ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK=1 "
        "for automation after reading those documents."
    )
    parser = argparse.ArgumentParser(
        prog="slop-cli",
        description="Event-driven slop generation and notarization pipeline.",
        epilog=cli_epilog,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_pipeline_parsers(
        subparsers,
        default_repo_path=default_repo_path,
        read_env_optional=read_env_optional,
        env_path=env_path,
    )
    register_verification_parsers(subparsers, default_repo_path=default_repo_path)
    register_maintenance_parsers(subparsers, default_repo_path=default_repo_path)
    register_admin_parsers(subparsers)
    return parser
