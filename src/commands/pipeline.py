"""Generation, curation, and human-registration CLI commands."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
from pathlib import Path
from uuid import UUID

from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.adapters.gemini_engine import GeminiEngineAdapter
from src.adapters.git_ledger import GitLedgerAdapter
from src.domain.events import (
    StoryAnchored,
    StoryCommitted,
    StoryCurated,
    StoryHumanRegistered,
    StoryRequested,
    StorySigned,
    StoryTimestamped,
)
from src.infrastructure.event_bus import EventBus
from src.logging_config import bind_log_context, should_log_route
from src.models import AttestationQa, AuthorAttestation
from src.ports import ProvenanceServicePort
from src.secrets_guard import assert_secret_free
from src.services.curation_service import (
    build_curation_metadata,
    extract_markdown_body,
    extract_request_id_from_artifact_path,
)
from src.runtime.cli_command_runtime import (
    _capture_registration_ceremony,
    _default_repo_path,
    _print_attest_next_step,
    _read_env_optional,
    _resolve_tsa_ca_cert_path,
    _validate_artifact_under_repo,
    _verify_git_commit,
    build_dispatch_error_handler,
    build_provenance_command_runtime,
    create_story_committed_future,
)

_cli_logger = logging.getLogger("src.cli")


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
                verification_status=("verified" if timestamp_outcome.verification.ok else "failed"),
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
    if should_log_route("coarse"):
        repo_path = getattr(args, "repo_path", None) or _default_repo_path()
        _cli_logger.info(
            "command generate repo_path=%s model_id=%s",
            repo_path,
            getattr(args, "model_id", "-"),
            extra={"command": "generate"},
        )

    assert_secret_free("cli generate prompt", args.prompt)

    runtime = build_provenance_command_runtime(args, enforce_external_repo_path=True)
    event_bus = runtime.event_bus
    repository = runtime.repository
    telemetry_adapter = runtime.telemetry_adapter
    repository_path = runtime.repository_path
    provenance_service = runtime.provenance_service
    completion_future = create_story_committed_future()

    gemini_adapter = GeminiEngineAdapter(
        event_bus=event_bus,
        model_id=args.model_id,
        env_path=runtime.env_path,
    )
    notary_adapter = CryptoNotaryAdapter(event_bus=event_bus, env_path=runtime.env_path)
    ledger_adapter = GitLedgerAdapter(
        event_bus=event_bus,
        repository_path=repository_path,
        env_path=runtime.env_path,
    )

    async def _record_signed(event: StorySigned) -> None:
        if event.artifact.signature is None:
            raise RuntimeError("Signed artifact is missing signature block.")
        await asyncio.to_thread(
            repository.artifacts.create_artifact_record,
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
            _read_env_optional("SIGNING_KEY_VERSION", env_path=runtime.env_path),
        )

    async def _record_committed(event: StoryCommitted) -> None:
        try:
            commit_id = await asyncio.to_thread(
                _verify_git_commit,
                repository_path,
                event.commit_oid,
            )
            await asyncio.to_thread(
                repository.artifacts.update_artifact_status,
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

    await event_bus.subscribe(StorySigned, _record_signed)
    await event_bus.subscribe(StoryCommitted, _record_committed)
    await event_bus.subscribe_errors(build_dispatch_error_handler(completion_future))

    await gemini_adapter.start()
    await notary_adapter.start()
    await ledger_adapter.start()
    await telemetry_adapter.start()

    request_event = StoryRequested(prompt=args.prompt)
    bind_log_context(request_id=request_event.request_id)
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
    if should_log_route("coarse"):
        _cli_logger.info(
            "command curate file=%s repo_path=%s",
            getattr(args, "file", "-"),
            getattr(args, "repo_path", None) or _default_repo_path(),
            extra={"command": "curate"},
        )

    runtime = build_provenance_command_runtime(args, enforce_external_repo_path=True)
    event_bus = runtime.event_bus
    repository = runtime.repository
    telemetry_adapter = runtime.telemetry_adapter
    repository_path = runtime.repository_path
    provenance_service = runtime.provenance_service
    completion_future = create_story_committed_future()

    notary_adapter = CryptoNotaryAdapter(event_bus=event_bus, env_path=runtime.env_path)
    ledger_adapter = GitLedgerAdapter(
        event_bus=event_bus,
        repository_path=repository_path,
        env_path=runtime.env_path,
    )

    artifact_path = Path(args.file).resolve()
    _validate_artifact_under_repo(artifact_path, repository_path)
    if not artifact_path.exists():
        raise RuntimeError(f"Curated file not found: '{artifact_path}'.")

    request_id = extract_request_id_from_artifact_path(artifact_path)
    record = await asyncio.to_thread(
        repository.artifacts.get_artifact_record,
        request_id,
    )
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
            repository.artifacts.update_artifact_curation,
            event.request_id,
            event.body,
            event.artifact.signature.artifact_hash,
            event.artifact.signature.cryptographic_signature,
        )
        await asyncio.to_thread(
            provenance_service.register_signing_key,
            event.artifact.signature.verification_anchor.signer_fingerprint,
            _read_env_optional("SIGNING_KEY_VERSION", env_path=runtime.env_path),
        )

    async def _record_committed(event: StoryCommitted) -> None:
        try:
            commit_id = await asyncio.to_thread(
                _verify_git_commit,
                repository_path,
                event.commit_oid,
            )
            await asyncio.to_thread(
                repository.artifacts.update_artifact_status,
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

    await event_bus.subscribe(StorySigned, _record_signed)
    await event_bus.subscribe(StoryCommitted, _record_committed)
    await event_bus.subscribe_errors(build_dispatch_error_handler(completion_future))
    await telemetry_adapter.start()
    await notary_adapter.start()
    await ledger_adapter.start()

    bind_log_context(request_id=request_id)
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
    "Do you publicly declare ownership of this text, affirming that it is your original creation?"
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
    runtime = build_provenance_command_runtime(args, enforce_external_repo_path=True)
    event_bus = runtime.event_bus
    repository = runtime.repository
    telemetry_adapter = runtime.telemetry_adapter
    repository_path = runtime.repository_path
    provenance_service = runtime.provenance_service
    completion_future = create_story_committed_future()

    notary_adapter = CryptoNotaryAdapter(event_bus=event_bus, env_path=runtime.env_path)
    ledger_adapter = GitLedgerAdapter(
        event_bus=event_bus,
        repository_path=repository_path,
        env_path=runtime.env_path,
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
            attestations=[AttestationQa(question=q, answer=a) for q, a in qa_pairs],
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

    webauthn_attestation = None
    if not getattr(args, "no_webauthn", False):
        from src.canonicalization import canonicalize_body_for_hash
        from src.webauthn_attestation import get_webauthn_assertion

        challenge_bytes = canonicalize_body_for_hash(body)
        challenge_hash = hashlib.sha256(challenge_bytes).digest()
        print("Insert your security key and touch it to complete attestation...")
        webauthn_attestation = get_webauthn_assertion(
            challenge=challenge_hash,
            repo_path=repository_path,
            env_path=runtime.env_path,
        )
        if webauthn_attestation is None:
            print(
                "WebAuthn skipped (set WEBAUTHN_RP_ID to your production domain, "
                "or no device/fido2). Using legacy."
            )
        else:
            print("WebAuthn attestation captured.")

    async def _record_signed(event: StorySigned) -> None:
        if event.artifact.signature is None:
            raise RuntimeError("Signed artifact is missing signature block.")
        await asyncio.to_thread(
            repository.artifacts.create_artifact_record,
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
            _read_env_optional("SIGNING_KEY_VERSION", env_path=runtime.env_path),
        )

    async def _record_committed(event: StoryCommitted) -> None:
        try:
            commit_id = await asyncio.to_thread(
                _verify_git_commit,
                repository_path,
                event.commit_oid,
            )
            await asyncio.to_thread(
                repository.artifacts.update_artifact_status,
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

    ceremony = _capture_registration_ceremony(runtime.env_path)
    human_event = StoryHumanRegistered(
        body=body,
        title=title,
        license=args.license,
        attestation=attestation,
        webauthn_attestation=webauthn_attestation,
        registration_ceremony=ceremony,
    )

    if should_log_route("coarse"):
        _cli_logger.info(
            "command register file=%s repo_path=%s",
            getattr(args, "file", "-"),
            getattr(args, "repo_path", None) or _default_repo_path(),
            extra={"command": "register"},
        )

    await event_bus.subscribe(StorySigned, _record_signed)
    await event_bus.subscribe(StoryCommitted, _record_committed)
    await event_bus.subscribe_errors(build_dispatch_error_handler(completion_future))
    await telemetry_adapter.start()
    await notary_adapter.start()
    await ledger_adapter.start()

    bind_log_context(request_id=human_event.request_id)
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
