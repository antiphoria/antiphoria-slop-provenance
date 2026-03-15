"""Command-line entry point for the Slop Orchestrator.

This module composes the event bus and adapters, exposes a simple argparse UX,
and executes the asynchronous generation->notarization->ledger pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import time
import uuid as uuid_module
from pathlib import Path
from uuid import UUID

import pygit2

from src.adapters.c2pa_manifest import (
    build_c2pa_validation_payload,
    validate_c2pa_sidecar,
)
from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.adapters.gemini_engine import GeminiEngineAdapter
from src.adapters.git_ledger import GitLedgerAdapter
from src.adapters.key_registry import KeyRegistryAdapter
from src.adapters.provenance_telemetry import ProvenanceTelemetryAdapter
from src.adapters.rfc3161_tsa import RFC3161TSAAdapter
from src.adapters.transparency_log import (
    TransparencyLogAdapter,
    build_supabase_publish_config,
)
from src.adapters.ots_adapter import OTSAdapter, build_ots_adapter, resolve_ots_binary
from src.env_config import (
    get_project_env_path,
    read_env_bool,
    read_env_optional,
    resolve_artifact_db_path,
)
from src.events import (
    EventBus,
    EventHandlerError,
    StoryAnchored,
    StoryAudited,
    StoryCommitted,
    StoryCurated,
    StoryHumanRegistered,
    StoryRequested,
    StorySigned,
    StoryTimestamped,
)
from src.models import AttestationQa, AuthorAttestation, RegistrationCeremony, sha256_hex
from src.parsing import parse_artifact_markdown, produce_redacted_artifact
from src.ports import ProvenanceServicePort
from src.repository import SQLiteRepository
from src.secrets_guard import assert_secret_free
from src.services.curation_service import (
    build_curation_metadata,
    extract_markdown_body,
    extract_request_id_from_artifact_path,
)
from src.adapters.ots_queue import OtsQueueAdapter
from src.merkle import build_merkle_root
from src.services.ots_upgrade import process_single_ots_record
from src.services.provenance_service import ProvenanceService
from src.services.verification_service import VerificationService


_read_env_optional = read_env_optional
_read_env_bool = read_env_bool


def _default_repo_path() -> str | None:
    """Default --repo-path from LEDGER_REPO_PATH in .env."""
    return _read_env_optional("LEDGER_REPO_PATH", env_path=get_project_env_path())


def _capture_registration_ceremony(env_path: Path) -> RegistrationCeremony:
    """Capture proof-of-environment metadata for human registration."""
    registration_utc_ms = int(time.time() * 1000)
    project_root = env_path.parent
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=5,
        )
        git_commit = result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:  # noqa: BLE001
        git_commit = "unknown"
    machine_id_hash: str | None = None
    if read_env_bool("CAPTURE_MACHINE_ID", default=False, env_path=env_path):
        try:
            node = uuid_module.getnode()
            machine_id_hash = hashlib.sha256(
                str(node).encode("utf-8")
            ).hexdigest()
        except Exception:  # noqa: BLE001
            pass
    return RegistrationCeremony(
        registrationUtcMs=registration_utc_ms,
        orchestratorGitCommit=git_commit,
        machineIdHash=machine_id_hash,
    )


def _require_repo_path(args: argparse.Namespace) -> Path:
    """Resolve repo path from args or LEDGER_REPO_PATH. Raises if unset."""
    raw = getattr(args, "repo_path", None) or _default_repo_path()
    if not raw:
        raise RuntimeError(
            "Provide --repo-path or set LEDGER_REPO_PATH in .env"
        )
    return Path(raw).resolve()


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
                f"(lock: '{self._lock_path}'). "
                "If the previous process crashed, remove the lock file manually and retry."
            ) from exc
        if self._fd is None:
            raise RuntimeError(
                f"Failed to create orchestrator lock file: '{self._lock_path}'."
            )
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
    generate_parser.add_argument(
        "--repo-path",
        default=_default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    generate_parser.add_argument(
        "--model-id",
        default=_read_env_optional(
            "GENERATOR_MODEL_ID", env_path=get_project_env_path()
        )
        or "gemini-2.5-flash",
        help="Google AI Studio model identifier.",
    )

    curate_parser = subparsers.add_parser(
        "curate",
        help="Re-sign and commit a curated artifact markdown file.",
    )
    curate_parser.add_argument(
        "--file", required=True, help="Edited artifact file path."
    )
    curate_parser.add_argument(
        "--repo-path",
        default=_default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )

    register_parser = subparsers.add_parser(
        "register",
        help="Certify human-only content (no AI generation).",
    )
    register_parser.add_argument(
        "--file", required=True, help="Plain markdown file path."
    )
    register_parser.add_argument(
        "--repo-path",
        default=_default_repo_path(),
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
        default=_default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )

    timestamp_parser = subparsers.add_parser(
        "timestamp",
        help="Request and verify RFC3161 timestamp token.",
    )
    timestamp_parser.add_argument("--file", required=True, help="Artifact file path.")
    timestamp_parser.add_argument(
        "--repo-path",
        default=_default_repo_path(),
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
        default=_default_repo_path(),
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
        default=_default_repo_path(),
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
        default=_default_repo_path(),
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

    forge_status_parser = subparsers.add_parser(
        "forge-status",
        help="List OTS forge status (PENDING/FORGED) for artifacts.",
    )
    forge_status_parser.add_argument(
        "--repo-path",
        default=_default_repo_path(),
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
        default=_default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    upgrade_parser.add_argument(
        "--request-id",
        required=True,
        help="Artifact request UUID to upgrade.",
    )

    process_pending_parser = subparsers.add_parser(
        "process-pending",
        help="Batch upgrade all PENDING OTS records.",
    )
    process_pending_parser.add_argument(
        "--repo-path",
        default=_default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    process_pending_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum PENDING records to process.",
    )

    anchor_merkle_parser = subparsers.add_parser(
        "anchor-merkle-root",
        help="Compute Merkle root of transparency log and OTS-stamp it (CT-style).",
    )
    anchor_merkle_parser.add_argument(
        "--repo-path",
        default=_default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )

    verify_tlog_parser = subparsers.add_parser(
        "verify-transparency-log",
        help="Recompute Merkle root from transparency log and compare to expected.",
    )
    verify_tlog_parser.add_argument(
        "--repo-path",
        default=_default_repo_path(),
        help="Ledger repo path (default: LEDGER_REPO_PATH from .env).",
    )
    verify_tlog_parser.add_argument(
        "--merkle-root",
        required=True,
        help="Expected Merkle root (hex) to compare against.",
    )

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

    return parser


def _verify_git_commit(repository_path: Path, commit_oid: str) -> str:
    """Verify that the git ledger contains a specific commit OID."""

    try:
        repo = pygit2.Repository(str(repository_path.resolve()))
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(
            f"Unable to open git repository for verification: '{repository_path}'."
        ) from exc
    try:
        commit = repo.revparse_single(commit_oid)
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(f"Commit verification failed for oid={commit_oid}.") from exc
    return str(commit.id)


def _validate_artifact_under_repo(artifact_path: Path, repository_path: Path) -> None:
    """Ensure artifact is under repository (prevents path traversal)."""
    try:
        artifact_path.resolve().relative_to(repository_path.resolve())
    except ValueError:
        raise RuntimeError(
            f"Artifact path must be under repository: {artifact_path}"
        ) from None


def _validate_external_repo_path(repository_path: Path) -> None:
    """Ensure ledger path is external to orchestrator source repository."""

    orchestrator_root = Path(__file__).resolve().parents[1]
    if repository_path.resolve() == orchestrator_root:
        raise RuntimeError(
            "The ledger repository must be external to the orchestrator repository. "
            "Provide a separate path via --repo-path."
        )


def _build_repository() -> SQLiteRepository:
    """Build SQLite repository for shared artifact lifecycle (cache)."""

    env_path = get_project_env_path()
    project_root = env_path.parent
    artifact_db_path = resolve_artifact_db_path(
        env_path=env_path,
        project_root=project_root,
    )
    if artifact_db_path is None:
        artifact_db_path = (project_root / ".orchestrator-state" / "artifacts.db").resolve()
    artifact_db_path.parent.mkdir(parents=True, exist_ok=True)
    return SQLiteRepository(db_path=artifact_db_path)


def _build_provenance_services(
    repository: SQLiteRepository,
    repository_path: Path,
    tsa_url_override: str | None = None,
) -> tuple[ProvenanceService, VerificationService]:
    """Build provenance + verification services."""

    transparency_log_path = repository_path / ".provenance" / "transparency-log.jsonl"
    env_path = Path(__file__).resolve().parents[1] / ".env"
    publish_url = _read_env_optional("TRANSPARENCY_LOG_PUBLISH_URL", env_path=env_path)
    publish_headers, publish_supabase_format = build_supabase_publish_config(
        publish_url, env_path=env_path
    )
    transparency_log_adapter = TransparencyLogAdapter(
        log_path=transparency_log_path,
        publish_url=publish_url,
        publish_headers=publish_headers if publish_headers else None,
        publish_supabase_format=publish_supabase_format,
    )
    tsa_url = tsa_url_override or _read_env_optional(
        "RFC3161_TSA_URL", env_path=env_path
    )
    if tsa_url is not None and not tsa_url.strip():
        tsa_url = None
    tsa_untrusted_path = _read_env_optional(
        "RFC3161_TSA_UNTRUSTED_CERT_PATH", env_path=env_path
    )
    openssl_bin = _read_env_optional("OPENSSL_BIN", env_path=env_path) or "openssl"
    openssl_conf = _read_env_optional("OPENSSL_CONF", env_path=env_path)
    tsa_adapter = (
        None
        if tsa_url is None
        else RFC3161TSAAdapter(
            tsa_url=tsa_url,
            openssl_bin=openssl_bin,
            untrusted_cert_path=(
                None
                if tsa_untrusted_path is None
                else Path(tsa_untrusted_path).resolve()
            ),
            openssl_conf_path=(
                None if openssl_conf is None else Path(openssl_conf).resolve()
            ),
        )
    )
    key_registry = KeyRegistryAdapter(repository=repository)
    ots_adapter = None
    if _read_env_bool("ENABLE_OTS_FORGE", default=False, env_path=env_path):
        ots_bin = resolve_ots_binary(env_path=env_path)
        ots_adapter = OTSAdapter(ots_bin=ots_bin)
    provenance_service = ProvenanceService(
        repository=repository,
        transparency_log_adapter=transparency_log_adapter,
        tsa_adapter=tsa_adapter,
        key_registry=key_registry,
        ots_adapter=ots_adapter,
        env_path=env_path,
    )
    verification_service = VerificationService(
        repository=repository,
        transparency_log_adapter=transparency_log_adapter,
        tsa_adapter=tsa_adapter,
        key_registry=key_registry,
        artifact_verifier=CryptoNotaryAdapter(
            event_bus=EventBus(),
            env_path=env_path,
            require_private_key=False,
        ),
        ots_adapter=ots_adapter,
        env_path=env_path,
    )
    return provenance_service, verification_service


def _resolve_tsa_ca_cert_path(
    explicit_path: str | None,
    env_path: Path | None = None,
) -> Path | None:
    """Resolve optional TSA CA cert path from arg or env."""

    resolved_env = env_path or get_project_env_path()
    raw_path = explicit_path or _read_env_optional(
        "RFC3161_CA_CERT_PATH", env_path=resolved_env
    )
    if raw_path is None:
        return None
    return Path(raw_path).resolve()


def _print_attest_next_step(repository_path: Path, request_id: UUID) -> None:
    """Print one-click follow-up attestation command."""

    print(
        "Next step:",
        "slop-cli attest "
        f'--repo-path "{repository_path}" '
        f"--request-id {request_id}",
    )


async def _anchor_and_timestamp_committed_artifact(
    event_bus: EventBus,
    provenance_service: ProvenanceServicePort,
    repository_path: Path,
    committed_event: StoryCommitted,
) -> None:
    """Anchor and timestamp a committed artifact when TSA is configured."""

    anchor_outcome = await asyncio.to_thread(
        provenance_service.anchor_committed_artifact,
        repository_path,
        committed_event.commit_oid,
        committed_event.ledger_path,
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
            provenance_service.timestamp_committed_artifact,
            repository_path,
            committed_event.commit_oid,
            committed_event.ledger_path,
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
        await event_bus.emit(
            StoryTimestamped(
                request_id=committed_event.request_id,
                artifact_id=UUID(anchor_outcome.artifact_id),
                artifact_hash=anchor_outcome.artifact_hash,
                tsa_url=_read_env_optional("RFC3161_TSA_URL") or "unconfigured",
                digest_algorithm="sha256",
                verification_status="skipped",
                verification_message=str(exc),
            )
        )
        print(f"Timestamp skipped: {exc}")


async def _run_generate_command(args: argparse.Namespace) -> int:
    """Run full async pipeline for `generate`."""

    assert_secret_free("cli generate prompt", args.prompt)

    env_path = get_project_env_path()
    event_bus = EventBus()
    repository = _build_repository()
    telemetry_adapter = ProvenanceTelemetryAdapter(
        event_bus=event_bus, repository=repository
    )
    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)
    provenance_service, _ = _build_provenance_services(repository, repository_path)
    completion_future: asyncio.Future[StoryCommitted] = (
        asyncio.get_running_loop().create_future()
    )

    gemini_adapter = GeminiEngineAdapter(
        event_bus=event_bus, model_id=args.model_id, env_path=env_path
    )
    notary_adapter = CryptoNotaryAdapter(event_bus=event_bus, env_path=env_path)
    ledger_adapter = GitLedgerAdapter(
        event_bus=event_bus,
        repository_path=repository_path,
        env_path=env_path,
    )

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
            _read_env_optional("SIGNING_KEY_VERSION", env_path=env_path),
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
    _print_attest_next_step(repository_path, request_event.request_id)
    await event_bus.drain()
    return 0


async def _run_curate_command(args: argparse.Namespace) -> int:
    """Run curation pipeline for an edited markdown artifact file."""

    env_path = get_project_env_path()
    event_bus = EventBus()
    repository = _build_repository()
    telemetry_adapter = ProvenanceTelemetryAdapter(
        event_bus=event_bus, repository=repository
    )
    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)
    provenance_service, _ = _build_provenance_services(repository, repository_path)
    completion_future: asyncio.Future[StoryCommitted] = (
        asyncio.get_running_loop().create_future()
    )

    notary_adapter = CryptoNotaryAdapter(event_bus=event_bus, env_path=env_path)
    ledger_adapter = GitLedgerAdapter(
        event_bus=event_bus,
        repository_path=repository_path,
        env_path=env_path,
    )

    artifact_path = Path(args.file).resolve()
    _validate_artifact_under_repo(artifact_path, repository_path)
    if not artifact_path.exists():
        raise RuntimeError(f"Curated file not found: '{artifact_path}'.")

    request_id = extract_request_id_from_artifact_path(artifact_path)
    record = await asyncio.to_thread(repository.get_artifact_record, request_id)
    if record is None:
        raise RuntimeError(f"Artifact record not found for request_id={request_id}.")
    if record.model_id == "human":
        raise RuntimeError(
            "Human-registered artifacts cannot be curated. "
            "Register seals the file; use attest to verify."
        )

    markdown_text = artifact_path.read_text(encoding="utf-8")
    curated_body = extract_markdown_body(markdown_text)
    assert_secret_free("curation prompt", record.prompt)
    assert_secret_free("curation body", curated_body)
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
            _read_env_optional("SIGNING_KEY_VERSION", env_path=env_path),
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
            title=record.title if record.model_id == "human" else None,
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
    _print_attest_next_step(repository_path, request_id)
    await event_bus.drain()
    return 0


def _derive_register_title(body: str, filename: str) -> str:
    """Derive artifact title from body or filename."""

    first_line = body.strip().splitlines()[0].strip() if body.strip() else ""
    candidate = first_line.strip("# ").strip()[:50]
    if candidate:
        return candidate
    return Path(filename).stem or "Untitled"


# Canonical attestation questions for human registration. Stored verbatim in
# artifact frontmatter for legal record. Do not truncate or normalize.
_REGISTER_QUESTION_1 = (
    "Do you affirm that you are a human acting on your own behalf, "
    "and that you possess the artistic capacity to make these declarations?"
)
_REGISTER_QUESTION_2 = (
    "Do you publicly declare ownership of this text, "
    "affirming that it is your original creation?"
)
_REGISTER_QUESTION_3_TEMPLATE = (
    "Do you declare in good faith that this text is your independent creation, "
    "and that its content accurately reflects the classification ({}) "
    "you selected above?"
)
_REGISTER_QUESTION_4 = (
    "Do you fully understand and consent that this declaration will be "
    "cryptographically sealed into a public, append-only ledger, and that any future "
    "attempt to alter or delete this record will deliberately break the cryptographic "
    "chain of trust?"
)


def _build_attestation_qa(
    classification: str,
) -> list[tuple[str, str]]:
    """Return (question, answer) pairs for non-interactive default attestation."""
    q3 = _REGISTER_QUESTION_3_TEMPLATE.format(classification.upper())
    return [
        (_REGISTER_QUESTION_1, "y"),
        (_REGISTER_QUESTION_2, "y"),
        (q3, "y"),
        (_REGISTER_QUESTION_4, "y"),
    ]


async def _run_register_command(args: argparse.Namespace) -> int:
    """Run human-only certification pipeline."""

    env_path = get_project_env_path()
    event_bus = EventBus()
    repository = _build_repository()
    telemetry_adapter = ProvenanceTelemetryAdapter(
        event_bus=event_bus, repository=repository
    )
    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)
    provenance_service, _ = _build_provenance_services(repository, repository_path)
    completion_future: asyncio.Future[StoryCommitted] = (
        asyncio.get_running_loop().create_future()
    )

    notary_adapter = CryptoNotaryAdapter(event_bus=event_bus, env_path=env_path)
    ledger_adapter = GitLedgerAdapter(
        event_bus=event_bus,
        repository_path=repository_path,
        env_path=env_path,
    )

    artifact_path = Path(args.file).resolve()
    if not artifact_path.exists():
        raise RuntimeError(f"File not found: '{artifact_path}'.")

    raw_text = artifact_path.read_text(encoding="utf-8").lstrip("\ufeff")
    if raw_text.startswith("---\n"):
        try:
            body = extract_markdown_body(raw_text)
        except RuntimeError:
            raise RuntimeError(
                f"File has malformed frontmatter. For human-only registration, "
                f"use plain markdown or fix the frontmatter: '{artifact_path}'."
            ) from None
    else:
        body = raw_text.strip()
    if not body:
        raise RuntimeError(f"File body is empty: '{artifact_path}'.")

    assert_secret_free("artifact body", body)
    title = args.title or _derive_register_title(body, artifact_path.name)

    # --- Artistic attestation wizard ---
    if getattr(args, "non_interactive", False):
        qa_pairs = _build_attestation_qa("fiction")
        attestation = AuthorAttestation(
            classification="fiction",
            attestations=[
                AttestationQa(question=q, answer=a) for q, a in qa_pairs
            ],
        )
    else:
        try:
            print("\n" + "=" * 50)
            print("ARTISTIC ATTESTATION WIZARD")
            print("=" * 50)
            print("STEP 1: Artistic Classification")
            print(
                "To establish the proper artistic context for this public record, "
                "how do you classify the primary intent of this text? Select one:"
            )
            print("[1] Statement of Fact / Record (Intended as literal truth)")
            print("[2] Opinion / Commentary (Subjective analysis or belief)")
            print("[3] Creative Fiction / Art (Imaginative or literary work)")
            print("[4] Satire / Parody (Humorous or exaggerated critique)")
            class_choice = input("Enter 1-4: ").strip()
            class_map = {"1": "fact", "2": "opinion", "3": "fiction", "4": "satire"}
            if class_choice not in class_map:
                raise RuntimeError("Registration aborted: Invalid classification selected.")
            classification = class_map[class_choice]

            print("\nSTEP 2: The Attestations")
            questions = [
                _REGISTER_QUESTION_1,
                _REGISTER_QUESTION_2,
                _REGISTER_QUESTION_3_TEMPLATE.format(classification.upper()),
                _REGISTER_QUESTION_4,
            ]
            answers: list[str] = []
            for i, q in enumerate(questions, 1):
                raw = input(f"Prompt {i}: {q} [y/N]: ").strip()
                answers.append(raw)
                if raw.lower() != "y":
                    raise RuntimeError(
                        "Registration aborted: All attestations must be agreed to (y) to proceed."
                    )

            attestation = AuthorAttestation(
                classification=classification,
                attestations=[
                    AttestationQa(question=q, answer=a)
                    for q, a in zip(questions, answers, strict=True)
                ],
            )
            print("=" * 50 + "\n")
        except (KeyboardInterrupt, EOFError):
            print("\nRegistration aborted by user.")
            return 1

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
            _read_env_optional("SIGNING_KEY_VERSION", env_path=env_path),
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

    ceremony = _capture_registration_ceremony(env_path)
    human_event = StoryHumanRegistered(
        body=body,
        title=title,
        license=args.license,
        attestation=attestation,
        registration_ceremony=ceremony,
    )

    await event_bus.subscribe(StorySigned, _record_signed)
    await event_bus.subscribe(StoryCommitted, _record_committed)
    await event_bus.subscribe_errors(_record_dispatch_error)
    await telemetry_adapter.start()
    await notary_adapter.start()
    await ledger_adapter.start()

    await event_bus.emit(human_event)
    committed_event = await asyncio.wait_for(completion_future, timeout=300.0)
    await _anchor_and_timestamp_committed_artifact(
        event_bus=event_bus,
        provenance_service=provenance_service,
        repository_path=repository_path,
        committed_event=committed_event,
    )
    print(
        "Registration completed:",
        f"request_id={human_event.request_id}",
        f"commit={committed_event.commit_oid}",
        f"path={committed_event.ledger_path}",
    )
    _print_attest_next_step(repository_path, human_event.request_id)
    await event_bus.drain()
    return 0


async def _run_verify_command(args: argparse.Namespace) -> int:
    """Run strict signature verification for one artifact file."""

    env_path = get_project_env_path()
    adapter = CryptoNotaryAdapter(
        event_bus=EventBus(),
        env_path=env_path,
        require_private_key=False,
    )
    artifact_path = Path(args.file).resolve()
    allow_redacted = getattr(args, "allow_redacted", False)
    try:
        artifact_id = adapter.read_artifact_id(artifact_path)
        ok = adapter.verify_artifact(artifact_path, allow_redacted=allow_redacted)
        if not ok:
            print("[FAIL] CORRUPT ARTIFACT: Invalid ML-DSA signature")
            return 1
        if allow_redacted:
            print(
                "[OK] REDACTED: Metadata and signatures valid. "
                "Reveal full body to complete verification."
            )
            return 0
        envelope, payload = parse_artifact_markdown(artifact_path)
        sidecar_path = artifact_path.with_suffix(".c2pa")
        if sidecar_path.exists():
            validation_payload, validation_format = build_c2pa_validation_payload(
                envelope=envelope,
                body=payload,
            )
            c2pa_result = validate_c2pa_sidecar(
                payload_bytes=validation_payload,
                manifest_bytes=sidecar_path.read_bytes(),
                content_type=envelope.content_type,
                payload_format=validation_format,
                body_for_mvp=payload,
            )
            if not c2pa_result.valid and args.strict_c2pa:
                print(
                    "[FAIL] C2PA INVALID:",
                    "; ".join(c2pa_result.errors) or "unknown C2PA validation error",
                )
                return 1
            if c2pa_result.valid:
                print("[OK] C2PA VERIFIED: semantic validation passed")
            else:
                print(
                    "[WARN] C2PA INVALID:",
                    "; ".join(c2pa_result.errors) or "unknown C2PA validation error",
                )
        elif args.strict_c2pa:
            print("[FAIL] C2PA MISSING: strict C2PA verification requested")
            return 1
        print(f"[OK] SIGNATURE VERIFIED: {artifact_id} (Eternity v1)")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] CORRUPT ARTIFACT: {exc}")
        return 1


def _run_redact_command(args: argparse.Namespace) -> int:
    """Produce redacted artifact with body replaced by placeholder."""

    artifact_path = Path(args.file).resolve()
    output_path = Path(args.output).resolve()
    if not artifact_path.exists():
        print(f"[FAIL] File not found: {artifact_path}")
        return 1
    try:
        text = artifact_path.read_text(encoding="utf-8")
        redacted = produce_redacted_artifact(text, args.placeholder)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(redacted, encoding="utf-8")
        print(f"Redacted artifact written to: {output_path}")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] Redaction failed: {exc}")
        return 1


async def _run_anchor_command(args: argparse.Namespace) -> int:
    """Anchor one artifact hash in local/public transparency logs."""

    event_bus = EventBus()
    repository = _build_repository()
    telemetry_adapter = ProvenanceTelemetryAdapter(
        event_bus=event_bus, repository=repository
    )
    await telemetry_adapter.start()
    repository_path = _require_repo_path(args)
    provenance_service, _ = _build_provenance_services(repository, repository_path)
    artifact_path = Path(args.file).resolve()
    request_id = None
    try:
        request_id = extract_request_id_from_artifact_path(artifact_path)
    except RuntimeError:
        request_id = None
    if request_id is None:
        raise RuntimeError(
            "Cannot anchor: request_id could not be extracted from artifact path. "
            "Use <request_id>.md or YYYYMMDDTHHMMSSZ_<request_id>.md."
        )
    outcome = await asyncio.to_thread(
        provenance_service.anchor_artifact,
        artifact_path,
        request_id,
        repository_path,
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
    await event_bus.drain()
    return 0


async def _run_timestamp_command(args: argparse.Namespace) -> int:
    """Acquire and verify RFC3161 timestamp token for one artifact."""

    event_bus = EventBus()
    repository = _build_repository()
    telemetry_adapter = ProvenanceTelemetryAdapter(
        event_bus=event_bus, repository=repository
    )
    await telemetry_adapter.start()
    repository_path = _require_repo_path(args)
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
    await event_bus.drain()
    return 0 if outcome.verification.ok else 1


async def _run_audit_command(args: argparse.Namespace) -> int:
    """Run full-chain audit and emit machine-readable report."""

    event_bus = EventBus()
    repository = _build_repository()
    telemetry_adapter = ProvenanceTelemetryAdapter(
        event_bus=event_bus, repository=repository
    )
    await telemetry_adapter.start()
    repository_path = _require_repo_path(args)
    _, verification_service = _build_provenance_services(repository, repository_path)
    artifact_path = Path(args.file).resolve()
    _validate_artifact_under_repo(artifact_path, repository_path)
    report = await asyncio.to_thread(
        verification_service.audit_artifact,
        artifact_path,
        _resolve_tsa_ca_cert_path(args.tsa_ca_cert_path),
        repository_path,
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
    if args.strict_c2pa:
        passed = passed and report.c2pa_present and report.c2pa_valid
    artifact_uuid = None if not report.artifact_id else UUID(report.artifact_id)
    await event_bus.emit(
        StoryAudited(
            request_id=(None if report.request_id is None else UUID(report.request_id)),
            artifact_id=artifact_uuid,
            audit_passed=passed,
            report_path=None if args.report_file is None else str(report_path),
        )
    )
    await event_bus.drain()
    return 0 if passed else 1


def _attestation_verdict(
    report: object,
    strict: bool,
    strict_c2pa: bool,
) -> tuple[str, int]:
    """Compute user-facing attestation verdict and exit code."""

    critical_failure = (
        not (
            report.envelope_valid
            and report.signature_valid
            and report.payload_hash_match
            and report.transparency_anchor_found
            and report.transparency_log_integrity
        )
        or (report.remote_anchor_verified is False)
        or (report.key_status_at_signing_time == "revoked")
    )
    timestamp_failure = not (report.timestamp_found and report.timestamp_valid)
    c2pa_failure = strict_c2pa and not (report.c2pa_present and report.c2pa_valid)
    if critical_failure or c2pa_failure or (strict and timestamp_failure):
        return "FAIL", 1
    if timestamp_failure:
        return "WARN", 0
    if report.c2pa_present and not report.c2pa_valid:
        return "WARN", 0
    return "PASS", 0


async def _run_attest_command(args: argparse.Namespace) -> int:
    """Attest one branch artifact by request_id without branch checkout."""

    event_bus = EventBus()
    repository = _build_repository()
    telemetry_adapter = ProvenanceTelemetryAdapter(
        event_bus=event_bus, repository=repository
    )
    await telemetry_adapter.start()
    repository_path = _require_repo_path(args)
    _, verification_service = _build_provenance_services(repository, repository_path)

    try:
        request_id = UUID(str(args.request_id))
    except ValueError as exc:
        raise RuntimeError(f"Invalid request id '{args.request_id}'.") from exc

    report = await asyncio.to_thread(
        verification_service.audit_committed_artifact,
        repository_path,
        request_id,
        _resolve_tsa_ca_cert_path(args.tsa_ca_cert_path),
    )
    verdict, exit_code = _attestation_verdict(
        report,
        args.strict,
        args.strict_c2pa,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "verdict": verdict,
                    "strict": bool(args.strict),
                    "strict_c2pa": bool(args.strict_c2pa),
                    "report": report.to_dict(),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(
            f"[{verdict}] request_id={request_id} "
            f"artifact_id={report.artifact_id or '<unknown>'}"
        )
        if report.branch is not None and report.commit_oid is not None:
            print(
                "Branch context:",
                f"branch={report.branch}",
                f"commit={report.commit_oid}",
                f"path={report.ledger_path or report.source_file}",
            )
        print(
            "Checks:",
            f"signature={report.signature_valid}",
            f"payload_hash={report.payload_hash_match}",
            f"anchor={report.transparency_anchor_found}",
            f"log_integrity={report.transparency_log_integrity}",
            f"c2pa_present={report.c2pa_present}",
            f"c2pa_valid={report.c2pa_valid}",
            f"timestamp_found={report.timestamp_found}",
            f"timestamp_valid={report.timestamp_valid}",
            f"ots_forged={report.ots_forged}",
            f"bitcoin_block_height={report.bitcoin_block_height or '—'}",
            f"key_status={report.key_status_at_signing_time}",
        )
        if report.ots_forged and report.bitcoin_block_height is not None:
            print(f"OTS: Anchored to Bitcoin Block {report.bitcoin_block_height:,}")
        elif request_id:
            env_path = Path(__file__).resolve().parents[1] / ".env"
            ots_queue = OtsQueueAdapter(
                repository_path=repository_path,
                env_path=env_path,
            )
            ots_record = ots_queue.get_ots_forge_record(request_id)
            if ots_record and ots_record.status == "PENDING":
                print("OTS: Pending (descending into the Mempool)")
        if report.c2pa_validation_state is not None:
            print("C2PA state:", report.c2pa_validation_state)
        for c2pa_error in report.c2pa_errors:
            print(f"- C2PA: {c2pa_error}")
        for error in report.errors:
            print(f"- {error}")

    artifact_uuid = None if not report.artifact_id else UUID(report.artifact_id)
    await event_bus.emit(
        StoryAudited(
            request_id=request_id,
            artifact_id=artifact_uuid,
            audit_passed=verdict == "PASS",
            report_path=None,
        )
    )
    await event_bus.drain()
    return exit_code


async def _run_upgrade_command(args: argparse.Namespace) -> int:
    """Upgrade a single PENDING OTS artifact by request ID."""

    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)

    repository = _build_repository()
    env_path = Path(__file__).resolve().parents[1] / ".env"
    provenance_service, _ = _build_provenance_services(repository, repository_path)
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
    if record.status != "PENDING":
        block_str = (
            f" block={record.bitcoin_block_height}"
            if record.bitcoin_block_height
            else ""
        )
        print(f"Already {record.status}{block_str}")
        return 0

    semaphore = asyncio.Semaphore(1)
    await process_single_ots_record(
        semaphore,
        record,
        repository,
        ots_queue,
        provenance_service,
        ots_adapter,
        provenance_service.transparency_log_adapter,
        repository_path,
        ".provenance/ots-{request_id}.ots",
        bus=None,
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
    env_path = Path(__file__).resolve().parents[1] / ".env"
    provenance_service, _ = _build_provenance_services(repository, repository_path)
    ots_adapter = build_ots_adapter(env_path)
    if ots_adapter is None:
        print("OTS forging is disabled (ENABLE_OTS_FORGE=false).")
        return 1

    ots_queue = OtsQueueAdapter(
        repository_path=repository_path,
        env_path=env_path,
    )
    records = ots_queue.get_pending_records(limit=args.limit)
    if not records:
        print("No PENDING records.")
        return 0

    semaphore = asyncio.Semaphore(1)
    await asyncio.gather(
        *[
            process_single_ots_record(
                semaphore,
                r,
                repository,
                ots_queue,
                provenance_service,
                ots_adapter,
                provenance_service.transparency_log_adapter,
                repository_path,
                ".provenance/ots-{request_id}.ots",
                bus=None,
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


def _run_forge_status_command(args: argparse.Namespace) -> int:
    """List OTS forge status for PENDING and FORGED artifacts."""

    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)
    env_path = Path(__file__).resolve().parents[1] / ".env"
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
    """Compute Merkle root of transparency log, OTS-stamp it, commit to repo."""

    repository_path = _require_repo_path(args)
    _validate_external_repo_path(repository_path)
    env_path = Path(__file__).resolve().parents[1] / ".env"
    ots_adapter = build_ots_adapter(env_path)
    if ots_adapter is None:
        print("OTS forging is disabled (ENABLE_OTS_FORGE=false).")
        return 1

    log_path = repository_path / ".provenance" / "transparency-log.jsonl"
    if not log_path.exists():
        print("No transparency log found. Run anchor on artifacts first.")
        return 1

    transparency_log = TransparencyLogAdapter(log_path=log_path)
    entries = transparency_log.parse_entries_from_jsonl(
        log_path.read_text(encoding="utf-8")
    )
    if not entries:
        print("Transparency log is empty.")
        return 0

    entry_hashes = [e.entry_hash for e in entries]
    merkle_root = build_merkle_root(entry_hashes)
    root_bytes = bytes.fromhex(merkle_root)

    try:
        ots_bytes = ots_adapter.stamp_payload(root_bytes)
    except Exception as exc:  # noqa: BLE001
        print(f"OTS stamp failed: {exc}")
        return 1

    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ots_rel = f".provenance/merkle-{ts}.ots"
    ots_full = repository_path / ots_rel
    ots_full.parent.mkdir(parents=True, exist_ok=True)
    ots_full.write_bytes(ots_bytes)

    snapshots_path = repository_path / ".provenance" / "merkle-snapshots.jsonl"
    snapshot = {
        "merkle_root": merkle_root,
        "entry_count": len(entries),
        "anchored_at": datetime.now(timezone.utc).isoformat(),
        "ots_path": ots_rel,
        "bitcoin_block_height": None,
    }
    line = json.dumps(snapshot, sort_keys=True) + "\n"
    snapshots_path.parent.mkdir(parents=True, exist_ok=True)
    with open(snapshots_path, "a", encoding="utf-8") as f:
        f.write(line)

    repo = pygit2.Repository(str(repository_path))
    repo.index.add(ots_rel)
    repo.index.add(snapshots_path.relative_to(repository_path).as_posix())
    author = pygit2.Signature(
        "Slop Orchestrator",
        "bot@antiphoria.local",
    )
    repo.index.write()
    tree_id = repo.index.write_tree()
    try:
        parent = repo.head.target if repo.head else None
        ref_name = repo.head.name if repo.head else "refs/heads/master"
    except (KeyError, pygit2.GitError):
        parent = None
        ref_name = "HEAD"  # Empty repo: create initial commit
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


def _run_verify_transparency_log_command(args: argparse.Namespace) -> int:
    """Recompute Merkle root from transparency log and compare to expected."""

    repository_path = _require_repo_path(args)
    log_path = repository_path / ".provenance" / "transparency-log.jsonl"
    if not log_path.exists():
        print("No transparency log found.")
        return 1

    transparency_log = TransparencyLogAdapter(log_path=log_path)
    entries = transparency_log.parse_entries_from_jsonl(
        log_path.read_text(encoding="utf-8")
    )
    if not entries:
        print("Transparency log is empty.")
        return 1

    entry_hashes = [e.entry_hash for e in entries]
    computed_root = build_merkle_root(entry_hashes)
    expected = args.merkle_root.strip().lower()

    if computed_root.lower() == expected:
        print(f"OK: Merkle root matches ({len(entries)} entries)")
        return 0
    print(
        f"MISMATCH: computed={computed_root}, expected={expected} "
        f"({len(entries)} entries)"
    )
    return 1


async def _run_events_command(args: argparse.Namespace) -> int:
    """List recent provenance lifecycle telemetry events."""

    repository = _build_repository()
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


def _run_admin_revoke_key_command(args: argparse.Namespace) -> int:
    """Revoke a signing key by fingerprint."""

    db_path = args.db_path
    if db_path is None:
        env_path = get_project_env_path()
        project_root = env_path.parent
        resolved = resolve_artifact_db_path(
            env_path=env_path,
            project_root=project_root,
        )
        db_path = (
            resolved
            if resolved is not None
            else (project_root / ".orchestrator-state" / "artifacts.db").resolve()
        )
    else:
        db_path = Path(db_path).resolve()

    if not db_path.exists():
        raise RuntimeError(f"State database not found at: {db_path}")

    repository = SQLiteRepository(db_path=db_path)
    key_registry = KeyRegistryAdapter(repository=repository)
    if key_registry.get_status(args.fingerprint) is None:
        raise RuntimeError(f"Key fingerprint not found in registry: {args.fingerprint}")

    key_registry.set_status(fingerprint=args.fingerprint, status="revoked")
    print(f"Key revoked: fingerprint={args.fingerprint}")
    return 0


async def _dispatch(args: argparse.Namespace) -> int:
    """Dispatch parsed CLI args to command handlers."""

    if args.command == "generate":
        return await _run_generate_command(args)
    if args.command == "curate":
        return await _run_curate_command(args)
    if args.command == "register":
        return await _run_register_command(args)
    if args.command == "verify":
        return await _run_verify_command(args)
    if args.command == "redact":
        return _run_redact_command(args)
    if args.command == "anchor":
        return await _run_anchor_command(args)
    if args.command == "timestamp":
        return await _run_timestamp_command(args)
    if args.command == "audit":
        return await _run_audit_command(args)
    if args.command == "attest":
        return await _run_attest_command(args)
    if args.command == "forge-status":
        return _run_forge_status_command(args)
    if args.command == "upgrade":
        return await _run_upgrade_command(args)
    if args.command == "process-pending":
        return await _run_process_pending_command(args)
    if args.command == "anchor-merkle-root":
        return _run_anchor_merkle_root_command(args)
    if args.command == "verify-transparency-log":
        return _run_verify_transparency_log_command(args)
    if args.command == "events":
        return await _run_events_command(args)
    if args.command == "admin":
        if args.admin_command == "revoke-key":
            return _run_admin_revoke_key_command(args)
        raise RuntimeError(f"Unsupported admin command: {args.admin_command}")
    raise RuntimeError(f"Unsupported command: {args.command}")


def main() -> int:
    """Parse arguments and run the asynchronous CLI dispatcher."""

    parser = build_parser()
    parsed_args = parser.parse_args()
    lock_base = Path.cwd()
    if getattr(parsed_args, "command", None) in {
        "generate",
        "curate",
        "register",
        "anchor",
        "anchor-merkle-root",
        "timestamp",
        "audit",
        "attest",
        "events",
        "upgrade",
        "process-pending",
        "verify-transparency-log",
    }:
        lock_base = _require_repo_path(parsed_args)
    lock_path = lock_base / ".slop-orchestrator.lock"
    with OrchestratorLock(lock_path):
        return asyncio.run(_dispatch(parsed_args))


if __name__ == "__main__":
    raise SystemExit(main())
