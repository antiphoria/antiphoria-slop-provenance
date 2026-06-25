"""Human-readable artifact catalog stored on the archive default branch.

The catalog lives at `.provenance/catalog.jsonl` on `main` (or CATALOG_REF).
Each line is one artifact row; upsert replaces by `requestId`. The catalog is
derived from artifact branches and is rebuildable via `slop-cli catalog index`.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pygit2
from filelock import FileLock

from src.env_config import read_env_optional
from src.git_tree_utils import commit_tree_file, ensure_branch_exists, tree_get_blob
from src.lock_paths import build_repo_ref_lock_path
from src.models import Artifact
from src.parsing import parse_artifact_markdown_text

_logger = logging.getLogger(__name__)

_CATALOG_RELATIVE_PATH = ".provenance/catalog.jsonl"
_DEFAULT_CATALOG_REF = "refs/heads/main"
_DEFAULT_LEDGER_AUTHOR_NAME = "Antiphoria Slop Provenance"
_DEFAULT_LEDGER_AUTHOR_EMAIL = "bot@antiphoria.local"
_CATALOG_GROWTH_WARN_EVERY_LINES = 10_000
_REQUEST_ID_KEY = "requestId"


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def build_catalog_row(
    envelope: Artifact,
    request_id: UUID | str,
    branch: str,
    commit_oid: str,
    *,
    has_c2pa: bool,
    has_process_narrative: bool,
) -> dict[str, Any]:
    """Build one catalog JSON object from a parsed artifact envelope."""

    rid = str(request_id)
    attestation_nature: str | None = None
    if envelope.provenance.author_attestation is not None:
        attestation_nature = envelope.provenance.author_attestation.attestation_nature

    artifact_hash = ""
    if envelope.signature is not None:
        artifact_hash = envelope.signature.artifact_hash

    row: dict[str, Any] = {
        _REQUEST_ID_KEY: rid,
        "title": envelope.title,
        "timestamp": envelope.timestamp.astimezone(UTC).isoformat(),
        "source": envelope.provenance.source,
        "provenanceGrade": envelope.provenance.provenance_grade,
        "attestationNature": attestation_nature,
        "modelId": envelope.provenance.model_id,
        "modelsUsed": envelope.provenance.models_used,
        "license": envelope.license,
        "branch": branch,
        "commitOid": commit_oid,
        "artifactHash": artifact_hash,
        "hasC2pa": has_c2pa,
        "hasProcessNarrative": has_process_narrative,
        # v3 (Gap 1): version-chain fields. None/absent on the first version
        # of a work; populated on superseding versions. chainRoot is the
        # stable identifier across all versions of a work.
        "chainRoot": (envelope.revision.chain_root if envelope.revision else rid),
        "sequence": (envelope.revision.sequence if envelope.revision else 1),
        "supersedes": (envelope.revision.supersedes if envelope.revision else None),
        # supersededBy is filled in on the prior version's row when this row is
        # indexed (see CatalogAdapter.upsert_row — the v1 row gets pointed at v2).
        "supersededBy": None,
        "indexedAt": _utc_now_iso(),
    }
    return row


def _canonical_jsonl_line(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def _parse_entries(content: str) -> dict[str, dict[str, Any]]:
    """Parse JSONL; latest line per requestId wins."""

    latest: dict[str, dict[str, Any]] = {}
    for line_index, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            _logger.warning(
                "Skipping malformed catalog JSON line %d: %s",
                line_index,
                exc,
            )
            continue
        if not isinstance(obj, dict):
            _logger.warning("Skipping catalog line %d: expected JSON object", line_index)
            continue
        request_id = obj.get(_REQUEST_ID_KEY)
        if not request_id:
            _logger.warning("Skipping catalog line %d without requestId", line_index)
            continue
        latest[str(request_id)] = obj
    return latest


def _render_entries(entries: dict[str, dict[str, Any]]) -> str:
    sorted_rows = sorted(
        entries.values(),
        key=lambda row: str(row.get("timestamp") or ""),
    )
    lines = [_canonical_jsonl_line(row) for row in sorted_rows]
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


class CatalogAdapter:
    """Git-backed artifact catalog on the archive default branch."""

    def __init__(
        self,
        repository_path: Path,
        catalog_ref: str | None = None,
        env_path: Path | None = None,
    ) -> None:
        self._repository_path = repository_path.resolve()
        self._catalog_ref = (
            catalog_ref
            or read_env_optional("CATALOG_REF", env_path=env_path)
            or _DEFAULT_CATALOG_REF
        )
        self._env_path = env_path
        self._catalog_path = self._repository_path / _CATALOG_RELATIVE_PATH

    def _resolve_commit_signature(self, repo: pygit2.Repository) -> pygit2.Signature:
        name = read_env_optional("LEDGER_AUTHOR_NAME", env_path=self._env_path)
        email = read_env_optional("LEDGER_AUTHOR_EMAIL", env_path=self._env_path)
        try:
            name = name or repo.config["user.name"]
            email = email or repo.config["user.email"]
        except KeyError:
            pass
        name = name or _DEFAULT_LEDGER_AUTHOR_NAME
        email = email or _DEFAULT_LEDGER_AUTHOR_EMAIL
        return pygit2.Signature(name, email)

    def _open_repository(self) -> pygit2.Repository:
        return pygit2.Repository(str(self._repository_path))

    def _read_current_content(self, repo: pygit2.Repository) -> str:
        try:
            ref = repo.lookup_reference(self._catalog_ref)
            commit = ref.peel(pygit2.Commit)
        except (KeyError, pygit2.GitError, ValueError):
            return ""
        if not isinstance(commit, pygit2.Commit):
            return ""
        path_parts = Path(_CATALOG_RELATIVE_PATH).parts
        try:
            tree = commit.tree
            for part in path_parts:
                entry = tree[part]
                obj = repo[entry.id]
                if isinstance(obj, pygit2.Blob):
                    return bytes(obj.data).decode("utf-8")
                tree = obj
        except KeyError:
            return ""
        return ""

    def _ensure_branch_exists(self, repo: pygit2.Repository) -> None:
        sig = self._resolve_commit_signature(repo)
        if ensure_branch_exists(
            repo,
            self._catalog_ref,
            sig,
            "provenance: init catalog branch",
        ):
            _logger.info("Created branch %s for catalog", self._catalog_ref)

    def _commit_content(
        self,
        repo: pygit2.Repository,
        content: str,
        message: str,
    ) -> None:
        self._validate_jsonl(content)
        self._ensure_branch_exists(repo)
        sig = self._resolve_commit_signature(repo)
        commit_tree_file(
            repo,
            self._catalog_ref,
            _CATALOG_RELATIVE_PATH,
            content.encode("utf-8"),
            message,
            sig,
        )

    def _write_content(self, content: str, message: str) -> None:
        lock_path = build_repo_ref_lock_path(self._repository_path, self._catalog_ref)
        with FileLock(lock_path):
            repo = self._open_repository()
            self._commit_content(repo=repo, content=content, message=message)
            line_count = sum(1 for line in content.splitlines() if line.strip())
            if line_count > 0 and line_count % _CATALOG_GROWTH_WARN_EVERY_LINES == 0:
                _logger.warning(
                    "Catalog has grown to %d entries. Consider archival/compaction.",
                    line_count,
                )

    @staticmethod
    def _validate_jsonl(content: str) -> None:
        for i, line in enumerate(content.splitlines()):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL: line {i + 1} is not valid JSON: {exc}") from exc

    def upsert_entry(self, row: dict[str, Any]) -> None:
        """Upsert one catalog row by requestId and commit to Git.

        v3 (Gap 1): if the row carries a ``supersedes`` field, the prior
        version's row is also patched with ``supersededBy`` pointing at this
        new requestId. The prior artifact itself never changes — only its
        catalog index entry. This makes version chains queryable without
        walking every envelope.
        """

        request_id = row.get(_REQUEST_ID_KEY)
        if not request_id:
            raise RuntimeError("Catalog row must include requestId.")
        entries = _parse_entries(self.read_raw_content())
        entries[str(request_id)] = row

        supersedes = row.get("supersedes")
        if isinstance(supersedes, str) and supersedes:
            prior = entries.get(supersedes)
            if prior is not None:
                prior["supersededBy"] = str(request_id)

        content = _render_entries(entries)
        self._write_content(content, f"catalog: upsert {request_id}")

    def rebuild(self, rows: list[dict[str, Any]]) -> None:
        """Replace catalog content with rows keyed by requestId."""

        entries: dict[str, dict[str, Any]] = {}
        for row in rows:
            request_id = row.get(_REQUEST_ID_KEY)
            if not request_id:
                continue
            entries[str(request_id)] = row
        content = _render_entries(entries)
        self._write_content(content, f"catalog: full reindex ({len(entries)} artifacts)")

    def read_raw_content(self) -> str:
        repo = self._open_repository()
        return self._read_current_content(repo)

    def read_entries(self) -> list[dict[str, Any]]:
        """Return catalog rows sorted by timestamp ascending."""

        entries = _parse_entries(self.read_raw_content())
        return sorted(entries.values(), key=lambda row: str(row.get("timestamp") or ""))


def _blob_exists_on_commit(
    repo: pygit2.Repository,
    commit_obj: pygit2.Commit,
    relative_path: str,
) -> bool:
    return tree_get_blob(repo, commit_obj.tree, relative_path) is not None


def collect_catalog_rows_from_repo(repository_path: Path) -> tuple[list[dict[str, Any]], int]:
    """Scan artifact branches and build catalog rows. Returns (rows, skipped_count)."""

    repo = pygit2.Repository(str(repository_path.resolve()))
    rows: list[dict[str, Any]] = []
    skipped = 0
    for ref in repo.references:
        name = getattr(ref, "name", str(ref))
        if not name.startswith("refs/heads/artifact/"):
            continue
        request_id = name.removeprefix("refs/heads/artifact/")
        branch = f"artifact/{request_id}"
        try:
            reference = repo.lookup_reference(name)
            commit_obj = repo[reference.target]
        except (KeyError, pygit2.GitError):
            skipped += 1
            continue
        if not isinstance(commit_obj, pygit2.Commit):
            skipped += 1
            continue
        ledger_path = f"{request_id}.md"
        blob_obj = tree_get_blob(repo, commit_obj.tree, ledger_path)
        if blob_obj is None:
            skipped += 1
            continue
        markdown_text = bytes(blob_obj.data).decode("utf-8")
        try:
            envelope, _payload = parse_artifact_markdown_text(markdown_text)
        except (RuntimeError, ValueError):
            skipped += 1
            continue
        has_c2pa = _blob_exists_on_commit(repo, commit_obj, f"{request_id}.c2pa")
        has_process = _blob_exists_on_commit(repo, commit_obj, f"{request_id}.process.json")
        rows.append(
            build_catalog_row(
                envelope,
                request_id,
                branch,
                str(commit_obj.id),
                has_c2pa=has_c2pa,
                has_process_narrative=has_process
                or envelope.provenance.process_narrative_hash is not None,
            )
        )
    return rows, skipped
