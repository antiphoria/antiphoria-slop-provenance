"""Parser registration for OTS/transparency/maintenance commands."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def register_maintenance_parsers(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    default_repo_path: Callable[[], str | None],
) -> None:
    """Register maintenance command parsers on the root subparser."""
    forge_status_parser = subparsers.add_parser(
        "forge-status",
        help="List OTS forge status (PENDING/FORGED) for artifacts.",
    )
    forge_status_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path for OTS queue (default: LEDGER_REPO_PATH from .env).",
    )
    forge_status_parser.add_argument(
        "--request-id",
        default=None,
        help="Filter by artifact request UUID.",
    )
    forge_status_parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON output.",
    )

    upgrade_parser = subparsers.add_parser(
        "upgrade",
        help="Upgrade a single PENDING OTS artifact by request ID.",
    )
    upgrade_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    upgrade_parser.add_argument(
        "--request-id",
        required=True,
        help="Artifact request UUID to upgrade.",
    )
    upgrade_parser.add_argument(
        "--retry",
        action="store_true",
        help="Retry a FAILED record (otherwise upgrade only processes PENDING).",
    )
    upgrade_parser.add_argument(
        "--force",
        action="store_true",
        help="Re-run even when FORGED (e.g. to fix missing git commit).",
    )

    process_pending_parser = subparsers.add_parser(
        "process-pending",
        help="Batch upgrade all PENDING OTS records.",
    )
    process_pending_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    process_pending_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum PENDING records to process.",
    )
    process_pending_parser.add_argument(
        "--retry",
        action="store_true",
        help="Include FAILED records for retry (otherwise only PENDING).",
    )

    recover_failed_parser = subparsers.add_parser(
        "recover-failed",
        help="Append a pending event to a FAILED record (integrity-preserving reset).",
    )
    recover_failed_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    recover_failed_parser.add_argument(
        "--request-id",
        required=True,
        help="Artifact request UUID to recover.",
    )

    anchor_merkle_parser = subparsers.add_parser(
        "anchor-merkle-root",
        help="Compute Merkle root of transparency log and OTS-stamp it (CT-style).",
    )
    anchor_merkle_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )

    upgrade_merkle_parser = subparsers.add_parser(
        "upgrade-merkle-ots",
        help="Upgrade Merkle root OTS proof and optionally update Supabase.",
    )
    upgrade_merkle_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    upgrade_merkle_parser.add_argument(
        "--ots-path",
        help="Path to .ots file (default: latest from merkle-snapshots.jsonl).",
    )

    sync_tlog_parser = subparsers.add_parser(
        "sync-transparency-log",
        help="Republish local transparency log entries to Supabase if missing (idempotent).",
    )
    sync_tlog_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )

    verify_tlog_parser = subparsers.add_parser(
        "verify-transparency-log",
        help="Recompute Merkle root from transparency log and compare to expected.",
    )
    verify_tlog_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    verify_tlog_parser.add_argument(
        "--merkle-root",
        required=True,
        help="Expected Merkle root (hex) to compare against.",
    )

    verify_hash_parser = subparsers.add_parser(
        "verify-hash",
        help="Compute artifactHash from artifact file using documented canonicalization.",
    )
    verify_hash_parser.add_argument(
        "--file",
        required=True,
        help="Artifact markdown file path.",
    )

    verify_inclusion_parser = subparsers.add_parser(
        "verify-inclusion",
        help="Verify artifact is included in Merkle tree via inclusion proof.",
    )
    verify_inclusion_parser.add_argument(
        "--leaf-hash",
        required=True,
        help="Leaf hash (entry_hash from transparency log) to verify.",
    )
    verify_inclusion_parser.add_argument(
        "--merkle-root",
        required=True,
        help="Expected Merkle root (hex).",
    )
    verify_inclusion_parser.add_argument(
        "--proof",
        required=True,
        help="JSON array of sibling hashes from leaf to root.",
    )
    verify_inclusion_parser.add_argument(
        "--leaf-index",
        type=int,
        required=True,
        help="Index of the leaf in the transparency log (0-based).",
    )
    verify_inclusion_parser.add_argument(
        "--tree-size",
        type=int,
        default=None,
        help="Number of leaves in the tree (required for odd-sized trees).",
    )

    build_proof_parser = subparsers.add_parser(
        "build-inclusion-proof",
        help="Build Merkle inclusion proof for an artifact hash.",
    )
    build_proof_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    build_proof_parser.add_argument(
        "--artifact-hash",
        required=True,
        help="Artifact hash (payload SHA-256) or entry_hash to build proof for.",
    )
    build_proof_parser.add_argument(
        "--json",
        action="store_true",
        help="Output proof as JSON (proof array + leaf_index + merkle_root).",
    )

    webauthn_register_parser = subparsers.add_parser(
        "webauthn-register",
        help="Register a WebAuthn credential for author attestation (run once per device).",
    )
    webauthn_register_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (credentials stored in repo or ~/.config).",
    )
