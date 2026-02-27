"""Command-line entry point for the Slop Orchestrator.

This module composes the event bus and adapters, exposes a simple argparse UX,
and executes the asynchronous generation->notarization->ledger pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from uuid import UUID

import pygit2

from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.adapters.gemini_engine import GeminiEngineAdapter
from src.adapters.git_ledger import GitLedgerAdapter
from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.provenance_telemetry import ProvenanceTelemetryAdapter
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter
from src.adapters.transparency_log import TransparencyLogAdapter
from src.events import (
    EventBus,
    EventHandlerError,
    StoryAnchored,
    StoryAudited,
    StoryCommitted,
    StoryCurated,
    StoryRequested,
    StorySigned,
    StoryTimestamped,
)
from src.models import sha256_hex
from src.repository import SQLiteRepository
from src.services.curation_service import (
    build_curation_metadata,
    extract_markdown_body,
    extract_request_id_from_artifact_path,
)
from src.services.provenance_service import ProvenanceService, parse_artifact_markdown
from src.services.verification_service import VerificationService


class OrchestratorLock:
    """Exclusive lock to prevent concurrent orchestrator processes."""

    def __init__(self, lock_path: Path) -> None:
        self._lock_path = lock_path
        self._fd: int | None = None

    def __enter__(self) -> "OrchestratorLock":
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._fd = os.open(
                str(self._lock_path),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            )
        except FileExistsError as exc:
            raise RuntimeError(
                "Another orchestrator instance is already running "
                f"(lock: '{self._lock_path}')."
            ) from exc
        assert self._fd is not None
        os.write(self._fd, str(os.getpid()).encode("ascii"))
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._fd is not None:
            os.close(self._fd)
        try:
            self._lock_path.unlink()
        except FileNotFoundError:
            pass


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""

    parser = argparse.ArgumentParser(
        prog="slop-cli",
        description="Event-driven slop generation and notarization pipeline.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate, notarize, and commit a new artifact.",
    )
    generate_parser.add_argument("--prompt", required=True, help="Prompt text.")
    generate_parser.add_argument("--repo-path", required=True, help="Ledger repo path.")
    generate_parser.add_argument(
        "--model-id",
        default="gemini-2.5-flash",
        help="Google AI Studio model identifier.",
    )

    curate_parser = subparsers.add_parser(
        "curate",
        help="Re-sign and commit a curated artifact markdown file.",
    )
    curate_parser.add_argument("--file", required=True, help="Edited artifact file path.")
    curate_parser.add_argument("--repo-path", required=True, help="Ledger repo path.")

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify Eternity v1 artifact signature and payload integrity.",
    )
    verify_parser.add_argument("--file", required=True, help="Artifact file path.")

    anchor_parser = subparsers.add_parser(
        "anchor",
        help="Anchor one artifact hash in transparency log.",
    )
    anchor_parser.add_argument("--file", required=True, help="Artifact file path.")
    anchor_parser.add_argument("--repo-path", required=True, help="Ledger repo path.")

    timestamp_parser = subparsers.add_parser(
        "timestamp",
        help="Request and verify RFC3161 timestamp token.",
    )
    timestamp_parser.add_argument("--file", required=True, help="Artifact file path.")
    timestamp_parser.add_argument("--repo-path", required=True, help="Ledger repo path.")
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
    audit_parser.add_argument("--repo-path", required=True, help="Ledger repo path.")
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
    events_parser = subparsers.add_parser(
        "events",
        help="List recent provenance lifecycle events.",
    )
    events_parser.add_argument("--repo-path", required=True, help="Ledger repo path.")
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

    return parser


def _verify_git_commit(repository_path: Path, commit_oid: str) -> str:
    """Verify that the git ledger contains a specific commit OID."""

    try:
        repo = pygit2.Repository(str(repository_path.resolve()))
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(
            f"Unable to open git repository for verification: '{repository_path}'."
        ) from exc
    if repo.head_is_unborn:
        raise RuntimeError("Git repository contains no commits to verify.")
    try:
        commit = repo.revparse_single(commit_oid)
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(f"Commit verification failed for oid={commit_oid}.") from exc
    return str(commit.id)


def _validate_external_repo_path(repository_path: Path) -> None:
    """Ensure ledger path is external to orchestrator source repository."""

    orchestrator_root = Path(__file__).resolve().parents[1]
    if repository_path.resolve() == orchestrator_root:
        raise RuntimeError(
            "The ledger repository must be external to the orchestrator repository. "
            "Provide a separate path via --repo-path."
        )


def _build_provenance_services(
    repository: SQLiteRepository,
    repository_path: Path,
    tsa_url_override: str | None = None,
) -> tuple[ProvenanceService, VerificationService]:
    """Build provenance + verification services."""

    transparency_log_path = repository_path / ".provenance" / "transparency-log.jsonl"
    transparency_log_adapter = TransparencyLogAdapter(
        log_path=transparency_log_path,
        publish_url=os.getenv("TRANSPARENCY_LOG_PUBLISH_URL"),
    )
    tsa_url = tsa_url_override or os.getenv("RFC3161_TSA_URL")
    tsa_adapter = None if tsa_url is None else RFC3161TSAAdapter(tsa_url=tsa_url)
    key_registry = KeyRegistryAdapter(repository=repository)
    provenance_service = ProvenanceService(
        repository=repository,
        transparency_log_adapter=transparency_log_adapter,
        tsa_adapter=tsa_adapter,
        key_registry=key_registry,
    )
    verification_service = VerificationService(
        repository=repository,
        transparency_log_adapter=transparency_log_adapter,
        tsa_adapter=tsa_adapter,
        key_registry=key_registry,
    )
    return provenance_service, verification_service


def _resolve_tsa_ca_cert_path(explicit_path: str | None) -> Path | None:
    """Resolve optional TSA CA cert path from arg or env."""

    raw_path = explicit_path or os.getenv("RFC3161_CA_CERT_PATH")
    if raw_path is None:
        return None
    return Path(raw_path).resolve()


async def _anchor_and_timestamp_committed_artifact(
    event_bus: EventBus,
    provenance_service: ProvenanceService,
    repository_path: Path,
    committed_event: StoryCommitted,
) -> None:
    """Anchor and timestamp a committed artifact when TSA is configured."""

    artifact_path = repository_path / committed_event.ledger_path
    anchor_outcome = await asyncio.to_thread(
        provenance_service.anchor_artifact,
        artifact_path,
        committed_event.request_id,
    )
    await event_bus.emit(
        StoryAnchored(
            request_id=committed_event.request_id,
            artifact_id=UUID(anchor_outcome.artifact_id),
            artifact_hash=anchor_outcome.artifact_hash,
            transparency_entry_id=anchor_outcome.entry_id,
            transparency_entry_hash=anchor_outcome.entry_hash,
            log_path=anchor_outcome.log_path,
        )
    )
    print(
        "Anchored artifact:",
        f"entry_id={anchor_outcome.entry_id}",
        f"entry_hash={anchor_outcome.entry_hash}",
    )
    try:
        timestamp_outcome = await asyncio.to_thread(
            provenance_service.timestamp_artifact,
            artifact_path,
            committed_event.request_id,
            _resolve_tsa_ca_cert_path(None),
        )
        await event_bus.emit(
            StoryTimestamped(
                request_id=committed_event.request_id,
                artifact_id=UUID(anchor_outcome.artifact_id),
                artifact_hash=anchor_outcome.artifact_hash,
                tsa_url=timestamp_outcome.tsa_url,
                digest_algorithm=timestamp_outcome.digest_algorithm,
                verification_status=(
                    "verified" if timestamp_outcome.verification.ok else "failed"
                ),
                verification_message=timestamp_outcome.verification.message,
            )
        )
        print(
            "Timestamped artifact:",
            f"tsa={timestamp_outcome.tsa_url}",
            f"verified={timestamp_outcome.verification.ok}",
        )
    except RuntimeError as exc:
        print(f"Timestamp skipped: {exc}")


async def _run_generate_command(args: argparse.Namespace) -> int:
    """Run full async pipeline for `generate`."""

    event_bus = EventBus()
    repository = SQLiteRepository()
    telemetry_adapter = ProvenanceTelemetryAdapter(event_bus=event_bus, repository=repository)
    repository_path = Path(args.repo_path).resolve()
    _validate_external_repo_path(repository_path)
    provenance_service, _ = _build_provenance_services(repository, repository_path)
    completion_future: asyncio.Future[StoryCommitted] = asyncio.get_running_loop().create_future()

    gemini_adapter = GeminiEngineAdapter(event_bus=event_bus, model_id=args.model_id)
    notary_adapter = CryptoNotaryAdapter(event_bus=event_bus)
    ledger_adapter = GitLedgerAdapter(event_bus=event_bus, repository_path=repository_path)

    async def _record_signed(event: StorySigned) -> None:
        if event.artifact.signature is None:
            raise RuntimeError("Signed artifact is missing signature block.")
        await asyncio.to_thread(
            repository.create_artifact_record,
            event.request_id,
            "signed",
            event.artifact,
            event.artifact.provenance.generation_context.prompt,
            event.body,
            event.artifact.provenance.model_id,
        )
        await asyncio.to_thread(
            provenance_service.register_signing_key,
            event.artifact.signature.verification_anchor.signer_fingerprint,
            os.getenv("SIGNING_KEY_VERSION"),
        )

    async def _record_committed(event: StoryCommitted) -> None:
        try:
            commit_id = await asyncio.to_thread(
                _verify_git_commit,
                repository_path,
                event.commit_oid,
            )
            await asyncio.to_thread(
                repository.update_artifact_status,
                event.request_id,
                "committed",
                event.ledger_path,
                commit_id,
            )
            if not completion_future.done():
                completion_future.set_result(event)
        except Exception as exc:
            if not completion_future.done():
                completion_future.set_exception(exc)
            raise

    async def _record_dispatch_error(event: EventHandlerError) -> None:
        if completion_future.done():
            return
        completion_future.set_exception(
            RuntimeError(
                "Event handler failed: "
                f"event={event.event_type} "
                f"handler={event.handler_name} "
                f"type={event.error_type} "
                f"message={event.error_message}"
            )
        )

    await event_bus.subscribe(StorySigned, _record_signed)
    await event_bus.subscribe(StoryCommitted, _record_committed)
    await event_bus.subscribe_errors(_record_dispatch_error)

    await gemini_adapter.start()
    await notary_adapter.start()
    await ledger_adapter.start()
    await telemetry_adapter.start()

    request_event = StoryRequested(prompt=args.prompt)
    await event_bus.emit(request_event)
    committed_event = await asyncio.wait_for(completion_future, timeout=300.0)
    await _anchor_and_timestamp_committed_artifact(
        event_bus=event_bus,
        provenance_service=provenance_service,
        repository_path=repository_path,
        committed_event=committed_event,
    )
    print(
        "Pipeline completed:",
        f"request_id={request_event.request_id}",
        f"commit={committed_event.commit_oid}",
        f"path={committed_event.ledger_path}",
    )
    return 0


async def _run_curate_command(args: argparse.Namespace) -> int:
    """Run curation pipeline for an edited markdown artifact file."""

    event_bus = EventBus()
    repository = SQLiteRepository()
    telemetry_adapter = ProvenanceTelemetryAdapter(event_bus=event_bus, repository=repository)
    repository_path = Path(args.repo_path).resolve()
    _validate_external_repo_path(repository_path)
    provenance_service, _ = _build_provenance_services(repository, repository_path)
    completion_future: asyncio.Future[StoryCommitted] = asyncio.get_running_loop().create_future()

    notary_adapter = CryptoNotaryAdapter(event_bus=event_bus)
    ledger_adapter = GitLedgerAdapter(event_bus=event_bus, repository_path=repository_path)

    artifact_path = Path(args.file).resolve()
    if not artifact_path.exists():
        raise RuntimeError(f"Curated file not found: '{artifact_path}'.")

    request_id = extract_request_id_from_artifact_path(artifact_path)
    record = await asyncio.to_thread(repository.get_artifact_record, request_id)
    if record is None:
        raise RuntimeError(f"Artifact record not found for request_id={request_id}.")

    markdown_text = artifact_path.read_text(encoding="utf-8")
    curated_body = extract_markdown_body(markdown_text)
    curation_metadata = build_curation_metadata(record.body, curated_body)

    async def _record_signed(event: StorySigned) -> None:
        if event.artifact.signature is None:
            raise RuntimeError("Signed artifact is missing signature block.")
        await asyncio.to_thread(
            repository.update_artifact_curation,
            event.request_id,
            event.body,
            event.artifact.signature.artifact_hash,
            event.artifact.signature.cryptographic_signature,
        )
        await asyncio.to_thread(
            provenance_service.register_signing_key,
            event.artifact.signature.verification_anchor.signer_fingerprint,
            os.getenv("SIGNING_KEY_VERSION"),
        )

    async def _record_committed(event: StoryCommitted) -> None:
        try:
            commit_id = await asyncio.to_thread(
                _verify_git_commit,
                repository_path,
                event.commit_oid,
            )
            await asyncio.to_thread(
                repository.update_artifact_status,
                event.request_id,
                "committed",
                event.ledger_path,
                commit_id,
            )
            if not completion_future.done():
                completion_future.set_result(event)
        except Exception as exc:
            if not completion_future.done():
                completion_future.set_exception(exc)
            raise

    async def _record_dispatch_error(event: EventHandlerError) -> None:
        if completion_future.done():
            return
        completion_future.set_exception(
            RuntimeError(
                "Event handler failed: "
                f"event={event.event_type} "
                f"handler={event.handler_name} "
                f"type={event.error_type} "
                f"message={event.error_message}"
            )
        )

    await event_bus.subscribe(StorySigned, _record_signed)
    await event_bus.subscribe(StoryCommitted, _record_committed)
    await event_bus.subscribe_errors(_record_dispatch_error)
    await telemetry_adapter.start()
    await notary_adapter.start()
    await ledger_adapter.start()

    await event_bus.emit(
        StoryCurated(
            request_id=request_id,
            curated_body=curated_body,
            prompt=record.prompt,
            curation_metadata=curation_metadata,
            model_id=record.model_id,
        )
    )
    committed_event = await asyncio.wait_for(completion_future, timeout=300.0)
    await _anchor_and_timestamp_committed_artifact(
        event_bus=event_bus,
        provenance_service=provenance_service,
        repository_path=repository_path,
        committed_event=committed_event,
    )
    print(
        "Curation completed:",
        f"request_id={request_id}",
        f"commit={committed_event.commit_oid}",
        f"path={committed_event.ledger_path}",
    )
    return 0


async def _run_verify_command(args: argparse.Namespace) -> int:
    """Run strict signature verification for one artifact file."""

    adapter = CryptoNotaryAdapter(event_bus=EventBus(), require_private_key=False)
    artifact_path = Path(args.file).resolve()
    try:
        artifact_id = adapter.read_artifact_id(artifact_path)
        ok = adapter.verify_artifact(artifact_path)
        if not ok:
            print("[FAIL] CORRUPT ARTIFACT: Invalid ML-DSA signature")
            return 1
        print(f"[OK] SIGNATURE VERIFIED: {artifact_id} (Eternity v1)")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] CORRUPT ARTIFACT: {exc}")
        return 1


async def _run_anchor_command(args: argparse.Namespace) -> int:
    """Anchor one artifact hash in local/public transparency logs."""

    event_bus = EventBus()
    repository = SQLiteRepository()
    telemetry_adapter = ProvenanceTelemetryAdapter(event_bus=event_bus, repository=repository)
    await telemetry_adapter.start()
    repository_path = Path(args.repo_path).resolve()
    provenance_service, _ = _build_provenance_services(repository, repository_path)
    artifact_path = Path(args.file).resolve()
    request_id = None
    try:
        request_id = extract_request_id_from_artifact_path(artifact_path)
    except RuntimeError:
        request_id = None
    outcome = await asyncio.to_thread(
        provenance_service.anchor_artifact,
        artifact_path,
        request_id,
    )
    await event_bus.emit(
        StoryAnchored(
            request_id=request_id,
            artifact_id=UUID(outcome.artifact_id),
            artifact_hash=outcome.artifact_hash,
            transparency_entry_id=outcome.entry_id,
            transparency_entry_hash=outcome.entry_hash,
            log_path=outcome.log_path,
        )
    )
    print(
        "Anchor completed:",
        f"entry_id={outcome.entry_id}",
        f"entry_hash={outcome.entry_hash}",
        f"log={outcome.log_path}",
    )
    return 0


async def _run_timestamp_command(args: argparse.Namespace) -> int:
    """Acquire and verify RFC3161 timestamp token for one artifact."""

    event_bus = EventBus()
    repository = SQLiteRepository()
    telemetry_adapter = ProvenanceTelemetryAdapter(event_bus=event_bus, repository=repository)
    await telemetry_adapter.start()
    repository_path = Path(args.repo_path).resolve()
    provenance_service, _ = _build_provenance_services(
        repository,
        repository_path,
        tsa_url_override=args.tsa_url,
    )
    artifact_path = Path(args.file).resolve()
    request_id = None
    try:
        request_id = extract_request_id_from_artifact_path(artifact_path)
    except RuntimeError:
        request_id = None
    outcome = await asyncio.to_thread(
        provenance_service.timestamp_artifact,
        artifact_path,
        request_id,
        _resolve_tsa_ca_cert_path(args.tsa_ca_cert_path),
    )
    envelope, payload = parse_artifact_markdown(artifact_path)
    digest_hex = sha256_hex(payload.encode("utf-8"))
    await event_bus.emit(
        StoryTimestamped(
            request_id=request_id,
            artifact_id=envelope.id,
            artifact_hash=digest_hex,
            tsa_url=outcome.tsa_url,
            digest_algorithm=outcome.digest_algorithm,
            verification_status="verified" if outcome.verification.ok else "failed",
            verification_message=outcome.verification.message,
        )
    )
    print(
        "Timestamp completed:",
        f"created_at={outcome.created_at}",
        f"tsa={outcome.tsa_url}",
        f"verified={outcome.verification.ok}",
        f"message={outcome.verification.message}",
    )
    return 0 if outcome.verification.ok else 1


async def _run_audit_command(args: argparse.Namespace) -> int:
    """Run full-chain audit and emit machine-readable report."""

    event_bus = EventBus()
    repository = SQLiteRepository()
    telemetry_adapter = ProvenanceTelemetryAdapter(event_bus=event_bus, repository=repository)
    await telemetry_adapter.start()
    repository_path = Path(args.repo_path).resolve()
    _, verification_service = _build_provenance_services(repository, repository_path)
    artifact_path = Path(args.file).resolve()
    report = await asyncio.to_thread(
        verification_service.audit_artifact,
        artifact_path,
        _resolve_tsa_ca_cert_path(args.tsa_ca_cert_path),
    )
    report_json = json.dumps(report.to_dict(), indent=2, sort_keys=True)
    if args.report_file is None:
        print(report_json)
    else:
        report_path = Path(args.report_file).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report_json, encoding="utf-8")
        print(f"Audit report written to: {report_path}")

    passed = (
        report.envelope_valid
        and report.signature_valid
        and report.payload_hash_match
        and report.transparency_anchor_found
        and report.timestamp_found
        and report.timestamp_valid
    )
    artifact_uuid = None if not report.artifact_id else UUID(report.artifact_id)
    await event_bus.emit(
        StoryAudited(
            request_id=(
                None if report.request_id is None else UUID(report.request_id)
            ),
            artifact_id=artifact_uuid,
            audit_passed=passed,
            report_path=None if args.report_file is None else str(report_path),
        )
    )
    return 0 if passed else 1


async def _run_events_command(args: argparse.Namespace) -> int:
    """List recent provenance lifecycle telemetry events."""

    repository = SQLiteRepository()
    rows = await asyncio.to_thread(
        repository.list_provenance_event_logs,
        args.limit,
        args.event_type,
    )
    if args.json:
        print(json.dumps(rows, indent=2, sort_keys=True))
        return 0
    if not rows:
        print("No provenance events found.")
        return 0
    for row in rows:
        print(
            f"[{row['id']}] {row['created_at']} {row['event_type']} "
            f"request_id={row['request_id']} artifact_id={row['artifact_id']}"
        )
    return 0


async def _dispatch(args: argparse.Namespace) -> int:
    """Dispatch parsed CLI args to command handlers."""

    if args.command == "generate":
        return await _run_generate_command(args)
    if args.command == "curate":
        return await _run_curate_command(args)
    if args.command == "verify":
        return await _run_verify_command(args)
    if args.command == "anchor":
        return await _run_anchor_command(args)
    if args.command == "timestamp":
        return await _run_timestamp_command(args)
    if args.command == "audit":
        return await _run_audit_command(args)
    if args.command == "events":
        return await _run_events_command(args)
    raise RuntimeError(f"Unsupported command: {args.command}")


def main() -> int:
    """Parse arguments and run the asynchronous CLI dispatcher."""

    parser = build_parser()
    parsed_args = parser.parse_args()
    lock_base = Path.cwd()
    if getattr(parsed_args, "command", None) in {
        "generate",
        "curate",
        "anchor",
        "timestamp",
        "audit",
        "events",
    }:
        lock_base = Path(parsed_args.repo_path).resolve()
    lock_path = lock_base / ".slop-orchestrator.lock"
    with OrchestratorLock(lock_path):
        return asyncio.run(_dispatch(parsed_args))


if __name__ == "__main__":
    raise SystemExit(main())
