"""Shared runtime helpers for CLI command handlers."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import shutil
import subprocess
import time
import uuid as uuid_module
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import pygit2

from src.adapters.provenance_telemetry import ProvenanceTelemetryAdapter
from src.domain.events import EventHandlerError, StoryCommitted
from src.env_config import (
    get_project_env_path,
    read_env_bool,
    read_env_optional,
)
from src.infrastructure.event_bus import EventBus
from src.models import RegistrationCeremony
from src.repository.sqlite import SQLiteRepository
from src.runtime.cli_composition import (
    build_provenance_services as _compose_provenance_services,
)
from src.runtime.cli_composition import (
    build_repository as _compose_repository,
)
from src.runtime.cli_composition import (
    resolve_tsa_ca_cert_path as _compose_tsa_ca_cert_path,
)
from src.services.provenance_service import ProvenanceService
from src.services.verification_service import VerificationService

_logger = logging.getLogger(__name__)
_read_env_optional = read_env_optional
_read_env_bool = read_env_bool


def _default_repo_path() -> str | None:
    """Default --repo-path from LEDGER_REPO_PATH in .env."""
    return _read_env_optional(
        "LEDGER_REPO_PATH",
        env_path=get_project_env_path(),
    )


def _capture_registration_ceremony(env_path: Path) -> RegistrationCeremony:
    """Capture proof-of-environment metadata for human registration."""
    registration_utc_ms = int(time.time() * 1000)
    project_root = env_path.parent
    git_exe = shutil.which("git")
    if git_exe:
        try:
            result = subprocess.run(  # noqa: S603
                [git_exe, "rev-parse", "HEAD"],
                cwd=project_root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=5,
            )
            git_commit = (
                result.stdout.strip() if result.returncode == 0 else "unknown"
            )
        except (OSError, subprocess.SubprocessError):
            git_commit = "unknown"
    else:
        git_commit = "unknown"
    machine_id_hash: str | None = None
    if read_env_bool("CAPTURE_MACHINE_ID", default=False, env_path=env_path):
        try:
            node = uuid_module.getnode()
            machine_id_hash = hashlib.sha256(
                str(node).encode("utf-8")
            ).hexdigest()
        except Exception:
            _logger.debug("Machine id capture failed", exc_info=True)
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


def _verify_git_commit(repository_path: Path, commit_oid: str) -> str:
    """Verify that the git ledger contains a specific commit OID."""
    try:
        repo = pygit2.Repository(str(repository_path.resolve()))
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(
            
                "Unable to open git repository for verification: "
                f"'{repository_path}'."
            
        ) from exc
    try:
        commit = repo.revparse_single(commit_oid)
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(
            f"Commit verification failed for oid={commit_oid}."
        ) from exc
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
    orchestrator_root = Path(__file__).resolve().parents[2]
    if repository_path.resolve() == orchestrator_root:
        raise RuntimeError(
            "The ledger repository must be external to the orchestrator repository. "
            "Provide a separate path via --repo-path."
        )


def _build_repository() -> SQLiteRepository:
    """Build SQLite repository for shared artifact lifecycle (cache)."""
    return _compose_repository(env_path=get_project_env_path())


def _build_provenance_services(
    repository: SQLiteRepository,
    repository_path: Path,
    tsa_url_override: str | None = None,
) -> tuple[ProvenanceService, VerificationService]:
    """Build provenance + verification services."""
    return _compose_provenance_services(
        repository=repository,
        repository_path=repository_path,
        tsa_url_override=tsa_url_override,
        env_path=get_project_env_path(),
    )


def _resolve_tsa_ca_cert_path(
    explicit_path: str | None,
    env_path: Path | None = None,
) -> Path | None:
    """Resolve optional TSA CA cert path from arg or env."""
    return _compose_tsa_ca_cert_path(
        explicit_path=explicit_path,
        env_path=env_path,
    )


def _print_attest_next_step(repository_path: Path, request_id: UUID) -> None:
    """Print one-click follow-up attestation command."""
    print(
        "Next step:",
        (
            f'slop-cli attest --repo-path "{repository_path}" '
            f"--request-id {request_id}"
        ),
    )


@dataclass(frozen=True, slots=True)
class ProvenanceCommandRuntime:
    """Shared runtime objects used by many CLI command handlers."""

    env_path: Path
    event_bus: EventBus
    repository: SQLiteRepository
    telemetry_adapter: ProvenanceTelemetryAdapter
    repository_path: Path
    provenance_service: ProvenanceService
    verification_service: VerificationService


def build_provenance_command_runtime(
    args: argparse.Namespace,
    *,
    enforce_external_repo_path: bool,
    tsa_url_override: str | None = None,
) -> ProvenanceCommandRuntime:
    """Build event bus, repository, telemetry, and services for a CLI command."""
    env_path = get_project_env_path()
    event_bus = EventBus()
    repository = _build_repository()
    telemetry_adapter = ProvenanceTelemetryAdapter(
        event_bus=event_bus,
        store=repository.telemetry,
    )
    repository_path = _require_repo_path(args)
    if enforce_external_repo_path:
        _validate_external_repo_path(repository_path)
    provenance_service, verification_service = _build_provenance_services(
        repository,
        repository_path,
        tsa_url_override=tsa_url_override,
    )
    return ProvenanceCommandRuntime(
        env_path=env_path,
        event_bus=event_bus,
        repository=repository,
        telemetry_adapter=telemetry_adapter,
        repository_path=repository_path,
        provenance_service=provenance_service,
        verification_service=verification_service,
    )


def create_story_committed_future() -> asyncio.Future[StoryCommitted]:
    """Create the standard completion future used by pipeline handlers."""
    return asyncio.get_running_loop().create_future()


def build_dispatch_error_handler(
    completion_future: asyncio.Future[StoryCommitted],
) -> Callable[[EventHandlerError], asyncio.Future[None] | None]:
    """Create standard EventHandlerError wiring for completion-future commands."""

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

    return _record_dispatch_error
