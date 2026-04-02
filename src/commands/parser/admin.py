"""Parser registration for admin commands."""

from __future__ import annotations

import argparse


def register_admin_parsers(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register admin command parsers on the root subparser."""
    admin_parser = subparsers.add_parser(
        "admin",
        help="Admin operations (key revocation, etc.).",
    )
    admin_sub = admin_parser.add_subparsers(dest="admin_command", required=True)
    revoke_parser = admin_sub.add_parser(
        "revoke-key",
        help="Revoke a signing key by fingerprint.",
    )
    revoke_parser.add_argument(
        "--fingerprint",
        required=True,
        help="Signer fingerprint to revoke.",
    )
    revoke_parser.add_argument(
        "--db-path",
        default=None,
        help="Path to artifact DB (default: ARTIFACT_DB_PATH or ORCHESTRATOR_STATE_DIR).",
    )
