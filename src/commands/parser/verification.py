"""Parser registration for verification/attestation/audit commands."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def register_verification_parsers(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    default_repo_path: Callable[[], str | None],
) -> None:
    """Register verification command parsers on the root subparser."""
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify Eternity v1 artifact signature and payload integrity.",
    )
    verify_parser.add_argument("--file", required=True, help="Artifact file path.")
    verify_parser.add_argument(
        "--strict-c2pa",
        action="store_true",
        help="Require sidecar presence and valid C2PA semantic verification.",
    )
    verify_parser.add_argument(
        "--allow-redacted",
        action="store_true",
        help="Verify metadata and signatures only; skip payload hash check (for redacted artifacts).",
    )

    redact_parser = subparsers.add_parser(
        "redact",
        help="Produce a redacted copy with body replaced by placeholder; metadata and signatures unchanged.",
    )
    redact_parser.add_argument("--file", required=True, help="Artifact file path.")
    redact_parser.add_argument(
        "--placeholder",
        default="[REDACTED UNTIL EXHIBITION OPENING]",
        help="Placeholder text for redacted body (default: [REDACTED UNTIL EXHIBITION OPENING]).",
    )
    redact_parser.add_argument(
        "--output",
        required=True,
        help="Output path for redacted artifact.",
    )

    anchor_parser = subparsers.add_parser(
        "anchor",
        help="Anchor one artifact hash in transparency log.",
    )
    anchor_parser.add_argument("--file", required=True, help="Artifact file path.")
    anchor_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )

    timestamp_parser = subparsers.add_parser(
        "timestamp",
        help="Request and verify RFC3161 timestamp token.",
    )
    timestamp_parser.add_argument("--file", required=True, help="Artifact file path.")
    timestamp_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    timestamp_parser.add_argument(
        "--tsa-url",
        default=None,
        help="Optional RFC3161 TSA URL override.",
    )
    timestamp_parser.add_argument(
        "--tsa-ca-cert-path",
        default=None,
        help="Path to TSA CA certificate bundle.",
    )

    audit_parser = subparsers.add_parser(
        "audit",
        help="Generate machine-readable full-chain audit report.",
    )
    audit_parser.add_argument("--file", required=True, help="Artifact file path.")
    audit_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    audit_parser.add_argument(
        "--tsa-ca-cert-path",
        default=None,
        help="Path to TSA CA certificate bundle.",
    )
    audit_parser.add_argument(
        "--report-file",
        default=None,
        help="Optional audit report output path.",
    )
    audit_parser.add_argument(
        "--strict-c2pa",
        action="store_true",
        help="Fail audit when C2PA sidecar is missing or invalid.",
    )

    attest_parser = subparsers.add_parser(
        "attest",
        help="Attest one artifact branch by request_id without checkout.",
    )
    attest_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    attest_parser.add_argument(
        "--request-id",
        required=True,
        help="Artifact request UUID (maps to branch artifact/<request_id>).",
    )
    attest_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail attestation when timestamp is missing/invalid.",
    )
    attest_parser.add_argument(
        "--json",
        action="store_true",
        help="Print structured attestation JSON output.",
    )
    attest_parser.add_argument(
        "--tsa-ca-cert-path",
        default=None,
        help="Path to TSA CA certificate bundle.",
    )
    attest_parser.add_argument(
        "--strict-c2pa",
        action="store_true",
        help="Fail attestation when C2PA sidecar is missing or invalid.",
    )

    events_parser = subparsers.add_parser(
        "events",
        help="List recent provenance lifecycle events.",
    )
    events_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    events_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of events to return.",
    )
    events_parser.add_argument(
        "--event-type",
        default=None,
        help="Optional event type filter (StoryAnchored, StoryTimestamped, StoryAudited).",
    )
    events_parser.add_argument(
        "--json",
        action="store_true",
        help="Print full events as JSON.",
    )
