"""Parser registration for generation/curation/registration commands."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path


def register_pipeline_parsers(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    default_repo_path: Callable[[], str | None],
    read_env_optional: Callable[[str], str | None],
    env_path: Path,
) -> None:
    """Register pipeline command parsers on the root subparser.

    v3: `generate` and `curate` were removed (pre-release.md §1). The remaining
    pipeline commands are `register` (human) and `seal` (synthetic).
    """
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
        "--author",
        default=None,
        help=(
            "Rights holder / author pen name (Flaw F). Antiphoria warrants "
            "provenance; the author holds the license. Required for v3 seals "
            "that ship; omit only for legacy test runs."
        ),
    )
    register_parser.add_argument(
        "--supersedes",
        default=None,
        help=(
            "requestId of the prior version this artifact supersedes (Gap 1). "
            "When set, the prior artifact's payloadHash is resolved from the "
            "archive and embedded as a content commitment in this envelope. "
            "Cannot be combined with --reason omitted."
        ),
    )
    register_parser.add_argument(
        "--reason",
        default=None,
        choices=[
            "copyright-flag",
            "error-correction",
            "plagiarism-removal",
            "editorial",
            "legal",
            "other",
        ],
        help="Required when --supersedes is set. Why this version supersedes the prior.",
    )
    register_parser.add_argument(
        "--note",
        default=None,
        help="Optional free-text explanation of the supersession (signed into the envelope).",
    )
    register_parser.add_argument(
        "--non-interactive",
        action="store_true",
        help=(
            "Skip self-declaration wizard; record unattended registration only "
            "(for CI/automation, no Q&A captured)."
        ),
    )
    register_parser.add_argument(
        "--no-webauthn",
        action="store_true",
        help="Skip WebAuthn/FIDO2; use self-declaration prompts only.",
    )

    seal_parser = subparsers.add_parser(
        "seal",
        help=(
            "Seal LLM-only content with orchestration declaration "
            "(human orchestrator, machine-generated text)."
        ),
    )
    seal_parser.add_argument("--file", required=True, help="Plain markdown file path.")
    seal_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    seal_parser.add_argument(
        "--title",
        default=None,
        help="Artifact title (default: first line or filename).",
    )
    seal_parser.add_argument(
        "--license",
        default="CC0-1.0",
        help="Content license to apply (default: CC0-1.0).",
    )
    seal_parser.add_argument(
        "--author",
        default=None,
        help=(
            "Rights holder / orchestrator pen name (Flaw F). Optional for CC0 "
            "(public-domain dedication); recommended even then for attribution."
        ),
    )
    seal_parser.add_argument(
        "--supersedes",
        default=None,
        help="requestId of the prior version this artifact supersedes (Gap 1).",
    )
    seal_parser.add_argument(
        "--reason",
        default=None,
        choices=[
            "copyright-flag",
            "error-correction",
            "plagiarism-removal",
            "editorial",
            "legal",
            "other",
        ],
        help="Required when --supersedes is set.",
    )
    seal_parser.add_argument(
        "--note",
        default=None,
        help="Optional free-text explanation of the supersession.",
    )
    seal_parser.add_argument(
        "--models",
        default=None,
        help="Comma-separated model identifiers used in production (e.g. gemini-3.1-pro,composer-2.5).",
    )
    seal_parser.add_argument(
        "--process-file",
        default=None,
        help="Optional JSON file describing the generation process (stored unverified).",
    )
    seal_parser.add_argument(
        "--non-interactive",
        action="store_true",
        help=(
            "Skip orchestration declaration wizard; record unattended sealing only "
            "(for CI/automation, no Q&A captured)."
        ),
    )
    seal_parser.add_argument(
        "--no-webauthn",
        action="store_true",
        help="Skip WebAuthn/FIDO2; use orchestration declaration prompts only.",
    )

    # v3 (Gap 2): witness command. An independent operator adds their seal to an
    # existing artifact as a vote of confidence / independent warranty.
    witness_parser = subparsers.add_parser(
        "witness",
        help="Add your operator seal to an existing sealed artifact (independent warranty).",
    )
    witness_parser.add_argument(
        "--request-id",
        required=True,
        help="requestId of the artifact to witness (must already be sealed + committed).",
    )
    witness_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    witness_parser.add_argument(
        "--no-webauthn",
        action="store_true",
        help="Skip WebAuthn capture for this witness seal.",
    )
