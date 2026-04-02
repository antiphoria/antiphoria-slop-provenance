"""Command-line entry point for Antiphoria Slop Provenance."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from src.commands.admin import _run_admin_revoke_key_command
from src.commands.maintenance import (
    _run_anchor_merkle_root_command,
    _run_build_inclusion_proof_command,
    _run_forge_status_command,
    _run_process_pending_command,
    _run_recover_failed_command,
    _run_sync_transparency_log_command,
    _run_upgrade_command,
    _run_upgrade_merkle_ots_command,
    _run_verify_hash_command,
    _run_verify_inclusion_command,
    _run_verify_transparency_log_command,
    _run_webauthn_register_command,
)
from src.commands.parser import build_cli_parser
from src.commands.pipeline import (
    _run_curate_command,
    _run_generate_command,
    _run_register_command,
)
from src.commands import verification as verification_commands
from src.commands.verification import (
    _run_anchor_command,
    _run_audit_command,
    _run_events_command,
    _run_redact_command,
    _run_timestamp_command,
    _run_verify_command,
)
from src.env_config import get_project_env_path
from src.logging_config import bind_log_context, clear_log_context
from src.research_use_ack import (
    argv_requests_help_only,
    is_research_use_acknowledged,
    print_non_interactive_research_ack_hint,
    prompt_and_confirm_research_use,
    write_research_use_acknowledgment,
)
import src.runtime.cli_command_runtime as command_runtime
from src.runtime.cli_command_runtime import (
    _build_provenance_services,
    _build_repository,
    _default_repo_path,
    _read_env_optional,
    _require_repo_path,
    _resolve_tsa_ca_cert_path,
)
from src.runtime.cli_routing import (
    AsyncCommandHandler,
    SyncCommandHandler,
    dispatch_command,
)
from src.runtime.service_runtime import configure_logging


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
            raise RuntimeError(f"Failed to create orchestrator lock file: '{self._lock_path}'.")
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
    return build_cli_parser(
        default_repo_path=_default_repo_path,
        read_env_optional=_read_env_optional,
        env_path=get_project_env_path(),
    )


async def _run_attest_command(args: argparse.Namespace) -> int:
    """Compatibility wrapper for attest command helper patching in tests."""
    previous_build_repository = command_runtime._build_repository
    previous_build_services = command_runtime._build_provenance_services
    previous_require_repo = command_runtime._require_repo_path
    previous_resolve_tsa = command_runtime._resolve_tsa_ca_cert_path
    previous_default_repo = command_runtime._default_repo_path
    command_runtime._build_repository = _build_repository
    command_runtime._build_provenance_services = _build_provenance_services
    command_runtime._require_repo_path = _require_repo_path
    command_runtime._resolve_tsa_ca_cert_path = _resolve_tsa_ca_cert_path
    command_runtime._default_repo_path = _default_repo_path
    try:
        return await verification_commands._run_attest_command(args)
    finally:
        command_runtime._build_repository = previous_build_repository
        command_runtime._build_provenance_services = previous_build_services
        command_runtime._require_repo_path = previous_require_repo
        command_runtime._resolve_tsa_ca_cert_path = previous_resolve_tsa
        command_runtime._default_repo_path = previous_default_repo


_ASYNC_COMMAND_HANDLERS: dict[str, AsyncCommandHandler] = {
    "generate": _run_generate_command,
    "curate": _run_curate_command,
    "register": _run_register_command,
    "verify": _run_verify_command,
    "anchor": _run_anchor_command,
    "timestamp": _run_timestamp_command,
    "audit": _run_audit_command,
    "attest": _run_attest_command,
    "upgrade": _run_upgrade_command,
    "process-pending": _run_process_pending_command,
    "events": _run_events_command,
}

_SYNC_COMMAND_HANDLERS: dict[str, SyncCommandHandler] = {
    "redact": _run_redact_command,
    "forge-status": _run_forge_status_command,
    "recover-failed": _run_recover_failed_command,
    "anchor-merkle-root": _run_anchor_merkle_root_command,
    "upgrade-merkle-ots": _run_upgrade_merkle_ots_command,
    "sync-transparency-log": _run_sync_transparency_log_command,
    "verify-transparency-log": _run_verify_transparency_log_command,
    "verify-hash": _run_verify_hash_command,
    "verify-inclusion": _run_verify_inclusion_command,
    "build-inclusion-proof": _run_build_inclusion_proof_command,
    "webauthn-register": _run_webauthn_register_command,
}

_ADMIN_COMMAND_HANDLERS: dict[str, SyncCommandHandler] = {
    "revoke-key": _run_admin_revoke_key_command,
}


async def _dispatch(args: argparse.Namespace) -> int:
    """Dispatch parsed CLI args to command handlers."""
    bind_log_context(command=args.command)
    try:
        return await _dispatch_impl(args)
    finally:
        clear_log_context()


async def _dispatch_impl(args: argparse.Namespace) -> int:
    """Inner dispatch without context management."""
    return await dispatch_command(
        args=args,
        async_handlers=_ASYNC_COMMAND_HANDLERS,
        sync_handlers=_SYNC_COMMAND_HANDLERS,
        admin_handlers=_ADMIN_COMMAND_HANDLERS,
    )


def main() -> int:
    """Parse arguments and run the asynchronous CLI dispatcher."""
    argv = sys.argv[1:]
    if not argv_requests_help_only(argv):
        if not is_research_use_acknowledged():
            if not sys.stdin.isatty():
                print_non_interactive_research_ack_hint()
                return 2
            if not prompt_and_confirm_research_use():
                return 2
            write_research_use_acknowledgment()

    configure_logging()
    parser = build_parser()
    parsed_args = parser.parse_args()
    lock_base = Path.cwd()
    if getattr(parsed_args, "command", None) in {
        "generate",
        "curate",
        "register",
        "anchor",
        "anchor-merkle-root",
        "upgrade-merkle-ots",
        "timestamp",
        "audit",
        "attest",
        "events",
        "upgrade",
        "process-pending",
        "recover-failed",
        "sync-transparency-log",
        "verify-transparency-log",
        "build-inclusion-proof",
        "webauthn-register",
    }:
        lock_base = _require_repo_path(parsed_args)
    lock_path = lock_base / ".antiphoria-slop-provenance.lock"
    with OrchestratorLock(lock_path):
        return asyncio.run(_dispatch(parsed_args))


if __name__ == "__main__":
    raise SystemExit(main())
