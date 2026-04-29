"""OTS, transparency, Merkle, and utility CLI commands."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import sys
from datetime import UTC
from pathlib import Path
from uuid import UUID

import pygit2

from src.adapters.ots_adapter import build_ots_adapter
from src.adapters.ots_queue import OtsQueueAdapter
from src.adapters.transparency_log import (
    TransparencyLogAdapter,
    build_supabase_publish_config,
)
from src.env_config import get_project_env_path
from src.merkle import build_merkle_root
from src.parsing import parse_artifact_markdown
from src.runtime.cli_command_runtime import (
    _build_provenance_services,
    _build_repository,
    _read_env_optional,
    _require_repo_path,
    _validate_external_repo_path,
)
from src.services.ots_upgrade import process_single_ots_record

_logger = logging.getLogger(__name__)


def _warn_merkle_remote_config(exc: RuntimeError) -> None:
    """Surface Supabase config errors that previously were swallowed."""
    msg = str(exc)
    _logger.warning("Merkle remote step skipped (configuration): %s", msg)
    print(f"Warning: Merkle remote publish skipped: {msg}", file=sys.stderr)


def _warn_merkle_remote_publish_failed(context: str) -> None:
    """Tell the operator when HTTP publish failed (details already in adapter logs)."""
    _logger.warning("%s: remote call returned False", context)
    print(
        f"Warning: {context}. Local ledger is updated; check logs for remote error detail.",
        file=sys.stderr,
    )


async def _run_upgrade_command(args: argparse.Namespace) -> int:
    """Upgrade a single PENDING OTS artifact by request ID."""
    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)

    repository = _build_repository()
    env_path = get_project_env_path()
    provenance_service, _ = _build_provenance_services(
        repository,
        repository_path,
    )
    ots_adapter = build_ots_adapter(env_path)
    if ots_adapter is None:
        print("OTS forging is disabled (ENABLE_OTS_FORGE=false).")
        return 1

    ots_queue = OtsQueueAdapter(
        repository_path=repository_path,
        env_path=env_path,
    )
    request_id = UUID(str(args.request_id))
    record = ots_queue.get_ots_forge_record(request_id)
    if record is None:
        print(f"No OTS forge record for request_id={args.request_id}")
        return 1
    if record.status == "FORGED" and not getattr(args, "force", False):
        block_str = f" block={record.bitcoin_block_height}" if record.bitcoin_block_height else ""
        print(f"Already {record.status}{block_str}")
        return 0
    if record.status == "FAILED" and not getattr(args, "retry", False):
        print("Already FAILED (use --retry to retry)")
        return 0
    if (
        record.status != "PENDING"
        and record.status != "FAILED"
        and not (record.status == "FORGED" and getattr(args, "force", False))
    ):
        print(f"Unexpected status: {record.status}")
        return 1

    semaphore = asyncio.Semaphore(1)
    await process_single_ots_record(
        semaphore,
        record,
        repository.artifacts,
        repository.transparency,
        ots_queue,
        provenance_service,
        ots_adapter,
        provenance_service.transparency_log_adapter,
        repository_path,
        ".provenance/ots-{request_id}.ots",
    )

    updated = ots_queue.get_ots_forge_record(request_id)
    if updated is None:
        return 1
    if updated.status == "FORGED" and updated.bitcoin_block_height is not None:
        print(f"Forged: bitcoin_block_height={updated.bitcoin_block_height}")
        return 0
    if updated.status == "PENDING":
        print("Still pending, try again later.")
        return 0
    if updated.status == "FAILED":
        print("Upgrade failed.")
        return 1
    return 0


async def _run_process_pending_command(args: argparse.Namespace) -> int:
    """Batch upgrade all PENDING OTS records."""
    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)

    repository = _build_repository()
    env_path = get_project_env_path()
    provenance_service, _ = _build_provenance_services(
        repository,
        repository_path,
    )
    ots_adapter = build_ots_adapter(env_path)
    if ots_adapter is None:
        print("OTS forging is disabled (ENABLE_OTS_FORGE=false).")
        return 1

    ots_queue = OtsQueueAdapter(
        repository_path=repository_path,
        env_path=env_path,
    )
    records = list(ots_queue.get_pending_records(limit=args.limit))
    if getattr(args, "retry", False):
        failed = ots_queue.list_ots_forge_records(
            status="FAILED",
            limit=args.limit,
        )
        records = (records + failed)[: args.limit]
    if not records:
        msg = (
            "No PENDING or FAILED records."
            if getattr(args, "retry", False)
            else "No PENDING records. (Use --retry to include FAILED.)"
        )
        print(msg)
        return 0

    semaphore = asyncio.Semaphore(1)
    await asyncio.gather(
        *[
            process_single_ots_record(
                semaphore,
                r,
                repository.artifacts,
                repository.transparency,
                ots_queue,
                provenance_service,
                ots_adapter,
                provenance_service.transparency_log_adapter,
                repository_path,
                ".provenance/ots-{request_id}.ots",
            )
            for r in records
        ],
        return_exceptions=True,
    )

    upgraded = 0
    still_pending = 0
    failed_count = 0
    for r in records:
        updated = ots_queue.get_ots_forge_record(UUID(r.request_id))
        if updated:
            if updated.status == "FORGED":
                upgraded += 1
            elif updated.status == "PENDING":
                still_pending += 1
            elif updated.status == "FAILED":
                failed_count += 1
    print(f"Upgraded {upgraded}, still pending {still_pending}, failed {failed_count}")
    return 0


def _run_recover_failed_command(args: argparse.Namespace) -> int:
    """Append a pending event to a FAILED record, preserving integrity."""
    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)

    env_path = get_project_env_path()
    ots_queue = OtsQueueAdapter(
        repository_path=repository_path,
        env_path=env_path,
    )

    request_id = UUID(str(args.request_id))
    record = ots_queue.get_ots_forge_record(request_id)

    if record is None:
        print(f"No OTS forge record found for request_id={args.request_id}")
        return 1

    if record.status != "FAILED":
        print(f"Record is not FAILED (current status: {record.status}). No action taken.")
        return 0

    if not record.pending_ots_b64:
        print("Cannot recover: FAILED record is missing pending_ots_b64 data.")
        return 1

    ots_queue.append_pending(
        request_id=request_id,
        artifact_hash=record.artifact_hash,
        pending_ots_b64=record.pending_ots_b64,
    )

    print(
        f"Successfully appended new PENDING event for {request_id}. "
        "It will be retried on the next process-pending run."
    )
    return 0


def _run_forge_status_command(args: argparse.Namespace) -> int:
    """List OTS forge status for PENDING and FORGED artifacts."""
    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)
    env_path = get_project_env_path()
    ots_queue = OtsQueueAdapter(
        repository_path=repository_path,
        env_path=env_path,
    )

    if args.request_id:
        request_id = UUID(str(args.request_id))
        record = ots_queue.get_ots_forge_record(request_id)
        if record is None:
            print(f"No OTS forge record for request_id={args.request_id}")
            return 1
        records = [record]
    else:
        pending = ots_queue.list_ots_forge_records(status="PENDING", limit=100)
        forged = ots_queue.list_ots_forge_records(status="FORGED", limit=100)
        records = pending + forged

    if args.json:
        output = [
            {
                "request_id": r.request_id,
                "artifact_hash": r.artifact_hash,
                "status": r.status,
                "bitcoin_block_height": r.bitcoin_block_height,
                "created_at": r.created_at,
                "updated_at": r.updated_at,
            }
            for r in records
        ]
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    if not records:
        print("No OTS forge records found.")
        return 0

    for r in records:
        block_str = f" block={r.bitcoin_block_height}" if r.bitcoin_block_height else ""
        print(f"{r.request_id} {r.status}{block_str} {r.artifact_hash[:16]}...")
    return 0


def _run_anchor_merkle_root_command(args: argparse.Namespace) -> int:
    """Compute Merkle root of transparency log, OTS-stamp it, and commit."""
    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)
    env_path = get_project_env_path()
    ots_adapter = build_ots_adapter(env_path)
    if ots_adapter is None:
        print("OTS forging is disabled (ENABLE_OTS_FORGE=false).")
        return 1

    log_path = repository_path / ".provenance" / "transparency-log.jsonl"
    if not log_path.exists():
        print("No transparency log found. Run anchor on artifacts first.")
        return 1

    transparency_log = TransparencyLogAdapter(log_path=log_path)
    entries = transparency_log.parse_entries_from_jsonl(log_path.read_text(encoding="utf-8"))
    if not entries:
        print("Transparency log is empty.")
        return 0

    entry_hashes = [e.entry_hash for e in entries]
    merkle_root = build_merkle_root(entry_hashes)
    root_bytes = bytes.fromhex(merkle_root)

    try:
        ots_bytes = ots_adapter.request_ots_stamp(root_bytes)
    except Exception as exc:  # noqa: BLE001
        print(f"OTS stamp failed: {exc}")
        return 1

    from datetime import datetime

    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    ots_rel = f".provenance/merkle-{ts}.ots"
    ots_full = repository_path / ots_rel
    ots_full.parent.mkdir(parents=True, exist_ok=True)
    ots_full.write_bytes(ots_bytes)

    snapshots_path = repository_path / ".provenance" / "merkle-snapshots.jsonl"
    snapshot = {
        "merkle_root": merkle_root,
        "entry_count": len(entries),
        "anchored_at": datetime.now(UTC).isoformat(),
        "ots_path": ots_rel,
        "bitcoin_block_height": None,
    }
    line = json.dumps(snapshot, sort_keys=True) + "\n"
    snapshots_path.parent.mkdir(parents=True, exist_ok=True)
    with open(snapshots_path, "a", encoding="utf-8") as file_handle:
        file_handle.write(line)

    try:
        publish_url = _read_env_optional(
            "MERKLE_ANCHORS_PUBLISH_URL",
            env_path=env_path,
        )
        if not publish_url:
            base_url = _read_env_optional(
                "TRANSPARENCY_LOG_PUBLISH_URL",
                env_path=env_path,
            )
            if base_url and "transparency_log" in base_url:
                publish_url = base_url.replace(
                    "transparency_log",
                    "merkle_anchors",
                )
        if publish_url:
            publish_headers, _ = build_supabase_publish_config(
                publish_url,
                env_path=env_path,
            )
            if publish_headers:
                from src.adapters.transparency_log import publish_merkle_anchor

                published = publish_merkle_anchor(
                    root_hash=merkle_root,
                    entry_count=len(entries),
                    anchored_at=snapshot["anchored_at"],
                    ots_path=ots_rel,
                    bitcoin_block_height=None,
                    publish_url=publish_url,
                    publish_headers=publish_headers,
                )
                if published:
                    print("Merkle anchor published to remote.")
                else:
                    _warn_merkle_remote_publish_failed(
                        "Merkle anchor was not published to the remote",
                    )
    except RuntimeError as exc:
        _warn_merkle_remote_config(exc)

    repo = pygit2.Repository(str(repository_path))
    repo.index.add(ots_rel)
    repo.index.add(snapshots_path.relative_to(repository_path).as_posix())
    author = pygit2.Signature(
        "Antiphoria Slop Provenance",
        "bot@antiphoria.local",
    )
    repo.index.write()
    tree_id = repo.index.write_tree()
    try:
        parent = repo.head.target if repo.head else None
        ref_name = repo.head.name if repo.head else "refs/heads/master"
    except (KeyError, pygit2.GitError):
        parent = None
        ref_name = "HEAD"
    if parent is not None:
        repo.create_commit(
            ref_name,
            author,
            author,
            f"provenance: anchor Merkle root ({ts})",
            tree_id,
            [parent],
        )
    else:
        repo.create_commit(
            ref_name,
            author,
            author,
            f"provenance: anchor Merkle root ({ts})",
            tree_id,
            [],
        )

    print(f"Merkle root anchored: {merkle_root[:16]}... ({len(entries)} entries)")
    return 0


def _run_upgrade_merkle_ots_command(args: argparse.Namespace) -> int:
    """Upgrade Merkle root OTS proof and optionally update Supabase."""
    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)
    env_path = get_project_env_path()
    ots_adapter = build_ots_adapter(env_path)
    if ots_adapter is None:
        print("OTS forging is disabled (ENABLE_OTS_FORGE=false).")
        return 1

    ots_path: str
    merkle_root: str
    if getattr(args, "ots_path", None):
        ots_path = args.ots_path
        ots_full = repository_path / ots_path
        if not ots_full.exists():
            print(f"OTS file not found: {ots_full}")
            return 1
        snapshots_path = repository_path / ".provenance" / "merkle-snapshots.jsonl"
        if not snapshots_path.exists():
            print("Cannot determine merkle_root without merkle-snapshots.jsonl.")
            return 1
        for line in reversed(snapshots_path.read_text(encoding="utf-8").splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                snap = json.loads(line)
                if snap.get("ots_path") == ots_path:
                    merkle_root = snap.get("merkle_root", "")
                    break
            except json.JSONDecodeError:
                continue
        else:
            print(f"No snapshot found for {ots_path}. Set --ots-path to match.")
            return 1
    else:
        snapshots_path = repository_path / ".provenance" / "merkle-snapshots.jsonl"
        if not snapshots_path.exists():
            print("No merkle-snapshots.jsonl found. Run anchor-merkle-root first.")
            return 1
        lines = [
            item.strip()
            for item in snapshots_path.read_text(encoding="utf-8").splitlines()
            if item.strip()
        ]
        if not lines:
            print("merkle-snapshots.jsonl is empty.")
            return 1
        try:
            snap = json.loads(lines[-1])
        except json.JSONDecodeError:
            print("Invalid JSON in merkle-snapshots.jsonl.")
            return 1
        ots_path = snap.get("ots_path", "")
        merkle_root = snap.get("merkle_root", "")
        if not ots_path or not merkle_root:
            print("Latest snapshot missing ots_path or merkle_root.")
            return 1

    ots_full = repository_path / ots_path
    if not ots_full.exists():
        print(f"OTS file not found: {ots_full}")
        return 1

    pending_b64 = base64.b64encode(ots_full.read_bytes()).decode("ascii")
    root_bytes = bytes.fromhex(merkle_root)
    upgraded, final_ots_bytes, block_height = ots_adapter.upgrade_ots_proof(
        pending_b64, payload_bytes=root_bytes
    )
    if not upgraded or final_ots_bytes is None:
        print("OTS upgrade failed.")
        return 1
    ots_full.write_bytes(final_ots_bytes)
    if block_height is None:
        print("Still pending. Try again later.")
        return 0
    print(f"Upgraded: bitcoin_block_height={block_height}")

    try:
        publish_url = _read_env_optional(
            "MERKLE_ANCHORS_PUBLISH_URL",
            env_path=env_path,
        )
        if not publish_url:
            base_url = _read_env_optional(
                "TRANSPARENCY_LOG_PUBLISH_URL",
                env_path=env_path,
            )
            if base_url and "transparency_log" in base_url:
                publish_url = base_url.replace(
                    "transparency_log",
                    "merkle_anchors",
                )
        if publish_url:
            publish_headers, _ = build_supabase_publish_config(
                publish_url,
                env_path=env_path,
            )
            if publish_headers:
                from src.adapters.transparency_log import (
                    update_merkle_anchor_block_height,
                )

                updated = update_merkle_anchor_block_height(
                    root_hash=merkle_root,
                    bitcoin_block_height=block_height,
                    publish_url=publish_url,
                    publish_headers=publish_headers,
                )
                if updated:
                    print("Supabase merkle_anchors updated.")
                else:
                    _warn_merkle_remote_publish_failed(
                        "Merkle anchor block height was not updated on the remote",
                    )
    except RuntimeError as exc:
        _warn_merkle_remote_config(exc)
    return 0


def _run_sync_transparency_log_command(args: argparse.Namespace) -> int:
    """Republish local transparency log entries to Supabase if missing."""
    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)
    repository = _build_repository()
    provenance_service, _ = _build_provenance_services(
        repository,
        repository_path,
    )
    published, skipped = provenance_service.sync_transparency_log_to_remote(repository_path)
    print(f"Published: {published}, skipped (already present): {skipped}")
    return 0


def _run_verify_transparency_log_command(args: argparse.Namespace) -> int:
    """Recompute Merkle root from transparency log and compare to expected."""
    repository_path = _require_repo_path(args)
    log_path = repository_path / ".provenance" / "transparency-log.jsonl"
    if not log_path.exists():
        print("No transparency log found.")
        return 1

    transparency_log = TransparencyLogAdapter(log_path=log_path)
    entries = transparency_log.parse_entries_from_jsonl(log_path.read_text(encoding="utf-8"))
    if not entries:
        print("Transparency log is empty.")
        return 1

    entry_hashes = [e.entry_hash for e in entries]
    computed_root = build_merkle_root(entry_hashes)
    expected = args.merkle_root.strip().lower()

    if computed_root.lower() == expected:
        print(f"OK: Merkle root matches ({len(entries)} entries)")
        return 0
    print(f"MISMATCH: computed={computed_root}, expected={expected} ({len(entries)} entries)")
    return 1


def _run_verify_hash_command(args: argparse.Namespace) -> int:
    """Compute artifactHash from artifact file using canonicalization."""
    from src.canonicalization import compute_payload_hash

    artifact_path = Path(args.file).resolve()
    if not artifact_path.exists():
        print(f"File not found: {artifact_path}")
        return 1
    try:
        _, payload = parse_artifact_markdown(artifact_path)
    except RuntimeError as exc:
        print(f"Parse error: {exc}")
        return 1
    digest_hex = compute_payload_hash(payload)
    print(digest_hex)
    return 0


def _run_verify_inclusion_command(args: argparse.Namespace) -> int:
    """Verify artifact is included in Merkle tree via inclusion proof."""
    from src.merkle import verify_merkle_proof

    try:
        proof = json.loads(args.proof)
    except json.JSONDecodeError as exc:
        print(f"Invalid proof JSON: {exc}")
        return 1
    if not isinstance(proof, list):
        print("Proof must be a JSON array of hex strings.")
        return 1
    if not all(isinstance(item, str) for item in proof):
        print("Proof elements must be hex strings.")
        return 1
    valid = verify_merkle_proof(
        leaf_hash=args.leaf_hash.strip().lower(),
        proof=proof,
        root=args.merkle_root.strip().lower(),
        leaf_index=args.leaf_index,
        tree_size=getattr(args, "tree_size", None),
    )
    if valid:
        print("OK: Inclusion proof valid.")
        return 0
    print("FAIL: Inclusion proof invalid.")
    return 1


def _run_build_inclusion_proof_command(args: argparse.Namespace) -> int:
    """Build Merkle inclusion proof for an artifact hash."""
    from src.merkle import build_merkle_proof
    from src.merkle import build_merkle_root as build_merkle_root_for_proof

    repository_path = _require_repo_path(args)
    log_path = repository_path / ".provenance" / "transparency-log.jsonl"
    if not log_path.exists():
        print("No transparency log found.")
        return 1
    transparency_log = TransparencyLogAdapter(log_path=log_path)
    entries = transparency_log.parse_entries_from_jsonl(log_path.read_text(encoding="utf-8"))
    if not entries:
        print("Transparency log is empty.")
        return 1
    entry_hashes = [e.entry_hash for e in entries]
    target = args.artifact_hash.strip().lower()
    leaf_index = next(
        (
            i
            for i, entry in enumerate(entries)
            if entry.entry_hash == target or entry.artifact_hash == target
        ),
        None,
    )
    if leaf_index is None:
        print(f"Hash not found in transparency log: {target[:16]}...")
        return 1
    leaf_hash = entry_hashes[leaf_index]
    proof = build_merkle_proof(entry_hashes, leaf_index)
    merkle_root = build_merkle_root_for_proof(entry_hashes)
    if getattr(args, "json", False):
        output = {
            "proof": proof,
            "leaf_index": leaf_index,
            "leaf_hash": leaf_hash,
            "merkle_root": merkle_root,
            "tree_size": len(entry_hashes),
        }
        print(json.dumps(output, sort_keys=True))
    else:
        print(f"Proof: {json.dumps(proof)}")
        print(f"Leaf index: {leaf_index}")
        print(f"Leaf hash: {leaf_hash}")
        print(f"Merkle root: {merkle_root}")
    return 0


def _run_webauthn_register_command(args: argparse.Namespace) -> int:
    """Register a WebAuthn credential for author attestation."""
    from src.webauthn_attestation import register_webauthn_credential

    repository_path = _require_repo_path(args)
    env_path = get_project_env_path()
    print("Insert your security key and touch it to register...")
    if register_webauthn_credential(
        repo_path=repository_path,
        env_path=env_path,
    ):
        print("WebAuthn credential registered successfully.")
        return 0
    print(
        "WebAuthn registration failed. Set WEBAUTHN_RP_ID to your production domain "
        "(e.g. antiphoria-archive.com), ensure fido2 is installed (pip install fido2), "
        "and a FIDO2 device is connected."
    )
    return 1
