"""Parser registration for generation/curation/registration commands."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable


def register_pipeline_parsers(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    default_repo_path: Callable[[], str | None],
    read_env_optional: Callable[[str], str | None],
    env_path: Path,
) -> None:
    """Register pipeline command parsers on the root subparser."""
    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate, notarize, and commit a new artifact.",
    )
    generate_parser.add_argument("--prompt", required=True, help="Prompt text.")
    generate_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    generate_parser.add_argument(
        "--model-id",
        default=read_env_optional("GENERATOR_MODEL_ID", env_path=env_path) or "gemini-2.5-flash",
        help="Google AI Studio model identifier.",
    )

    curate_parser = subparsers.add_parser(
        "curate",
        help="Re-sign and commit a curated artifact markdown file.",
    )
    curate_parser.add_argument("--file", required=True, help="Edited artifact file path.")
    curate_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )

    register_parser = subparsers.add_parser(
        "register",
        help=("Register self-attested human-only content (no AI generation in pipeline)."),
    )
    register_parser.add_argument("--file", required=True, help="Plain markdown file path.")
    register_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    register_parser.add_argument(
        "--title",
        default=None,
        help="Artifact title (default: first line or filename).",
    )
    register_parser.add_argument(
        "--license",
        default="ARR",
        help="Content license to apply (e.g. ARR, CC-BY-4.0, CC0-1.0).",
    )
    register_parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Skip artistic attestation wizard; use defaults (for CI/automation).",
    )
    register_parser.add_argument(
        "--no-webauthn",
        action="store_true",
        help="Skip WebAuthn/FIDO2 attestation; use legacy (y/N) only.",
    )
