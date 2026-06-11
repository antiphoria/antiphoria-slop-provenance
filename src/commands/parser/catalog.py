"""Parser registration for catalog commands."""

from __future__ import annotations

import argparse
from collections.abc import Callable


def register_catalog_parsers(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    default_repo_path: Callable[[], str | None],
) -> None:
    """Register catalog command parsers on the root subparser."""

    catalog_parser = subparsers.add_parser(
        "catalog",
        help="Browse and rebuild the archive artifact catalog.",
    )
    catalog_sub = catalog_parser.add_subparsers(dest="catalog_command", required=True)

    index_parser = catalog_sub.add_parser(
        "index",
        help="Rebuild catalog from all artifact/* branches.",
    )
    index_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Archive git repository path.",
    )

    list_parser = catalog_sub.add_parser(
        "list",
        help="List catalog entries from main branch.",
    )
    list_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Archive git repository path.",
    )
    list_parser.add_argument(
        "--source",
        choices=("human", "synthetic", "hybrid"),
        default=None,
        help="Filter by provenance source.",
    )
    list_parser.add_argument(
        "--grade",
        choices=("recorded", "declared", "unattended"),
        default=None,
        help="Filter by provenance grade.",
    )
    list_parser.add_argument(
        "--since",
        default=None,
        help="Include entries with timestamp >= YYYY-MM-DD or ISO-8601.",
    )
    list_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum entries to return (default: 50).",
    )
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="Print entries as JSON.",
    )

    show_parser = catalog_sub.add_parser(
        "show",
        help="Show one catalog entry and suggested verify/attest commands.",
    )
    show_parser.add_argument(
        "--repo-path",
        default=default_repo_path(),
        help="Archive git repository path.",
    )
    show_parser.add_argument(
        "--request-id",
        required=True,
        help="Artifact request UUID.",
    )
    show_parser.add_argument(
        "--json",
        action="store_true",
        help="Print entry as JSON only (no verify/attest hints).",
    )
