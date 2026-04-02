"""Verification, attestation, audit, and telemetry CLI commands."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
from uuid import UUID

from src.adapters.c2pa_manifest import (
    build_c2pa_validation_payload,
    validate_c2pa_sidecar,
)
from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.adapters.ots_queue import OtsQueueAdapter
from src.domain.events import StoryAnchored, StoryAudited, StoryTimestamped
from src.env_config import get_project_env_path
from src.infrastructure.event_bus import EventBus
from src.logging_config import bind_log_context, should_log_route
from src.models import sha256_hex
from src.parsing import parse_artifact_markdown, produce_redacted_artifact
from src.runtime.cli_command_runtime import (
    _build_repository,
    _default_repo_path,
    _resolve_tsa_ca_cert_path,
    _validate_artifact_under_repo,
    build_provenance_command_runtime,
)
from src.services.curation_service import extract_request_id_from_artifact_path

_cli_logger = logging.getLogger("src.cli")


async def _run_verify_command(args: argparse.Namespace) -> int:
    """Run strict signature verification for one artifact file."""
    runtime_env = get_project_env_path()
    adapter = CryptoNotaryAdapter(
        event_bus=EventBus(),
        env_path=runtime_env,
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
    if should_log_route("coarse"):
        _cli_logger.info(
            "command anchor file=%s repo_path=%s",
            getattr(args, "file", "-"),
            getattr(args, "repo_path", None) or _default_repo_path(),
            extra={"command": "anchor"},
        )

    runtime = build_provenance_command_runtime(args, enforce_external_repo_path=False)
    await runtime.telemetry_adapter.start()
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
    bind_log_context(request_id=request_id)
    outcome = await asyncio.to_thread(
        runtime.provenance_service.anchor_artifact,
        artifact_path,
        request_id,
        runtime.repository_path,
    )
    await runtime.event_bus.emit(
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
    await runtime.event_bus.drain()
    return 0


async def _run_timestamp_command(args: argparse.Namespace) -> int:
    """Acquire and verify RFC3161 timestamp token for one artifact."""
    if should_log_route("coarse"):
        _cli_logger.info(
            "command timestamp file=%s repo_path=%s",
            getattr(args, "file", "-"),
            getattr(args, "repo_path", None) or _default_repo_path(),
            extra={"command": "timestamp"},
        )

    runtime = build_provenance_command_runtime(
        args,
        enforce_external_repo_path=False,
        tsa_url_override=args.tsa_url,
    )
    await runtime.telemetry_adapter.start()
    artifact_path = Path(args.file).resolve()
    request_id = None
    try:
        request_id = extract_request_id_from_artifact_path(artifact_path)
    except RuntimeError:
        request_id = None
    if request_id is not None:
        bind_log_context(request_id=request_id)
    outcome = await asyncio.to_thread(
        runtime.provenance_service.timestamp_artifact,
        artifact_path,
        request_id,
        _resolve_tsa_ca_cert_path(args.tsa_ca_cert_path),
    )
    envelope, payload = parse_artifact_markdown(artifact_path)
    digest_hex = sha256_hex(payload.encode("utf-8"))
    await runtime.event_bus.emit(
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
    await runtime.event_bus.drain()
    return 0 if outcome.verification.ok else 1


async def _run_audit_command(args: argparse.Namespace) -> int:
    """Run full-chain audit and emit machine-readable report."""
    if should_log_route("coarse"):
        _cli_logger.info(
            "command audit file=%s repo_path=%s",
            getattr(args, "file", "-"),
            getattr(args, "repo_path", None) or _default_repo_path(),
            extra={"command": "audit"},
        )

    runtime = build_provenance_command_runtime(args, enforce_external_repo_path=False)
    await runtime.telemetry_adapter.start()
    artifact_path = Path(args.file).resolve()
    _validate_artifact_under_repo(artifact_path, runtime.repository_path)
    report = await asyncio.to_thread(
        runtime.verification_service.audit_artifact,
        artifact_path,
        _resolve_tsa_ca_cert_path(args.tsa_ca_cert_path),
        runtime.repository_path,
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
    if report.request_id is not None:
        bind_log_context(request_id=report.request_id)
    await runtime.event_bus.emit(
        StoryAudited(
            request_id=(None if report.request_id is None else UUID(report.request_id)),
            artifact_id=artifact_uuid,
            audit_passed=passed,
            report_path=None if args.report_file is None else str(report_path),
        )
    )
    await runtime.event_bus.drain()
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
    if should_log_route("coarse"):
        _cli_logger.info(
            "command attest request_id=%s repo_path=%s",
            getattr(args, "request_id", "-"),
            getattr(args, "repo_path", None) or _default_repo_path(),
            extra={"command": "attest"},
        )

    runtime = build_provenance_command_runtime(args, enforce_external_repo_path=False)
    await runtime.telemetry_adapter.start()

    try:
        request_id = UUID(str(args.request_id))
    except ValueError as exc:
        raise RuntimeError(f"Invalid request id '{args.request_id}'.") from exc

    bind_log_context(request_id=request_id)

    report = await asyncio.to_thread(
        runtime.verification_service.audit_committed_artifact,
        runtime.repository_path,
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
            f"[{verdict}] request_id={request_id} artifact_id={report.artifact_id or '<unknown>'}"
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
            ots_queue = OtsQueueAdapter(
                repository_path=runtime.repository_path,
                env_path=runtime.env_path,
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
    await runtime.event_bus.emit(
        StoryAudited(
            request_id=request_id,
            artifact_id=artifact_uuid,
            audit_passed=verdict == "PASS",
            report_path=None,
        )
    )
    await runtime.event_bus.drain()
    return exit_code


async def _run_events_command(args: argparse.Namespace) -> int:
    """List recent provenance lifecycle telemetry events."""
    repository = _build_repository()
    rows = await asyncio.to_thread(
        repository.telemetry.list_provenance_event_logs,
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
