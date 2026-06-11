"""Catalog index/list/show commands for archive artifact lookup."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from uuid import UUID

from src.adapters.catalog import CatalogAdapter, collect_catalog_rows_from_repo
from src.env_config import get_project_env_path
from src.runtime.cli_command_runtime import _require_repo_path


def _resolve_repo_path(args: argparse.Namespace) -> Path:
    return _require_repo_path(args)


def _filter_entries(
    entries: list[dict[str, object]],
    *,
    source: str | None,
    grade: str | None,
    since: str | None,
    limit: int,
) -> list[dict[str, object]]:
    filtered: list[dict[str, object]] = []
    since_dt: datetime | None = None
    if since:
        since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
    for row in entries:
        if source is not None and row.get("source") != source:
            continue
        if grade is not None and row.get("provenanceGrade") != grade:
            continue
        if since_dt is not None:
            ts_raw = row.get("timestamp")
            if not isinstance(ts_raw, str):
                continue
            row_dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            if row_dt < since_dt:
                continue
        filtered.append(row)
    filtered.sort(key=lambda row: str(row.get("timestamp") or ""), reverse=True)
    if limit > 0:
        return filtered[:limit]
    return filtered


def _run_catalog_index_command(args: argparse.Namespace) -> int:
    repository_path = _resolve_repo_path(args)
    env_path = get_project_env_path()
    rows, skipped = collect_catalog_rows_from_repo(repository_path)
    adapter = CatalogAdapter(repository_path=repository_path, env_path=env_path)
    adapter.rebuild(rows)
    print(
        "Catalog indexed:",
        f"artifacts={len(rows)}",
        f"skipped={skipped}",
        f"path={repository_path / '.provenance' / 'catalog.jsonl'}",
    )
    return 0


def _run_catalog_list_command(args: argparse.Namespace) -> int:
    repository_path = _resolve_repo_path(args)
    env_path = get_project_env_path()
    adapter = CatalogAdapter(repository_path=repository_path, env_path=env_path)
    entries = adapter.read_entries()
    filtered = _filter_entries(
        entries,
        source=getattr(args, "source", None),
        grade=getattr(args, "grade", None),
        since=getattr(args, "since", None),
        limit=args.limit,
    )
    if args.json:
        print(json.dumps(filtered, indent=2, sort_keys=True))
        return 0
    if not filtered:
        print("No catalog entries matched.")
        return 0
    for row in filtered:
        print(
            f"{row.get('timestamp')}  {row.get('source')}  "
            f"{row.get('provenanceGrade')}  {row.get('requestId')}  {row.get('title')}"
        )
    return 0


def _run_catalog_show_command(args: argparse.Namespace) -> int:
    repository_path = _resolve_repo_path(args)
    env_path = get_project_env_path()
    request_id = str(UUID(args.request_id))
    adapter = CatalogAdapter(repository_path=repository_path, env_path=env_path)
    entries = {str(row.get("requestId")): row for row in adapter.read_entries()}
    row = entries.get(request_id)
    if row is None:
        raise RuntimeError(f"Catalog entry not found for request_id={request_id}.")
    if args.json:
        print(json.dumps(row, indent=2, sort_keys=True))
        return 0
    print(json.dumps(row, indent=2, sort_keys=True))
    ledger_path = f"{request_id}.md"
    print()
    print("Verify:")
    print(f"  slop-cli verify --file {repository_path / ledger_path}")
    print("Attest:")
    print(f"  slop-cli attest --repo-path {repository_path} --request-id {request_id}")
    return 0
