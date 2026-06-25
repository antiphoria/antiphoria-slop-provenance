"""Generation, curation, and human-registration CLI commands."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
from pathlib import Path
from uuid import UUID

from src.adapters.catalog import CatalogAdapter, build_catalog_row
from src.adapters.crypto_notary import CryptoNotaryAdapter
from src.adapters.git_ledger import GitLedgerAdapter
from src.domain.events import (
    StoryAnchored,
    StoryCommitted,
    StoryHumanRegistered,
    StorySigned,
    StorySyntheticSealed,
    StoryTimestamped,
)
from src.infrastructure.event_bus import EventBus
from src.logging_config import bind_log_context, should_log_route
from src.models import AttestationQa, AuthorAttestation, canonical_json_bytes, sha256_hex
from src.ports import ProvenanceServicePort
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
from src.secrets_guard import assert_secret_free
from src.services.curation_service import (
    extract_markdown_body,
    extract_request_id_from_artifact_path,
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


async def _upsert_catalog_entry(
    repository_path: Path,
    env_path: Path,
    committed_event: StoryCommitted,
    signed_event: StorySigned,
) -> None:
    """Upsert one catalog row after commit; non-fatal on failure."""

    try:
        has_c2pa = signed_event.c2pa_manifest_bytes_b64 is not None
        has_process = (
            signed_event.process_narrative_bytes_b64 is not None
            or signed_event.process_narrative_hash is not None
            or signed_event.artifact.provenance.process_narrative_hash is not None
        )
        row = build_catalog_row(
            signed_event.artifact,
            committed_event.request_id,
            f"artifact/{committed_event.request_id}",
            committed_event.commit_oid,
            has_c2pa=has_c2pa,
            has_process_narrative=has_process,
        )
        adapter = CatalogAdapter(repository_path=repository_path, env_path=env_path)
        await asyncio.to_thread(adapter.upsert_entry, row)
    except Exception as exc:
        _cli_logger.warning(
            "Catalog upsert skipped for request_id=%s: %s",
            committed_event.request_id,
            exc,
        )


async def _maybe_upsert_catalog_after_commit(
    repository_path: Path,
    env_path: Path,
    committed_event: StoryCommitted,
    signed_by_request: dict[UUID, StorySigned],
) -> None:
    """Upsert catalog row when the signed artifact is available."""

    signed_event = signed_by_request.get(committed_event.request_id)
    if signed_event is None:
        return
    await _upsert_catalog_entry(
        repository_path,
        env_path,
        committed_event,
        signed_event,
    )


async def _run_witness_command(args: argparse.Namespace) -> int:
    """Witness an existing sealed artifact by appending an independent operator seal.

    v3 (Gap 2): the witnessing operator loads the artifact from its branch,
    runs full-chain verification (refuses to witness anything broken — a
    witness is a vote of confidence), loads their own keys, computes a fresh
    ML-DSA + Ed25519 seal over the same canonical target the sealer signed,
    appends it to ``operatorSeals[]``, and commits the augmented envelope.

    The original sealer's seal is never touched — witnessing is append-only.
    """

    if should_log_route("coarse"):
        _cli_logger.info(
            "command witness request_id=%s repo_path=%s",
            getattr(args, "request_id", "-"),
            getattr(args, "repo_path", None) or _default_repo_path(),
            extra={"command": "witness"},
        )

    runtime = build_provenance_command_runtime(args, enforce_external_repo_path=True)
    repository_path = runtime.repository_path
    request_id = str(args.request_id)

    # 1. Load the existing artifact from its branch.
    import pygit2

    try:
        repo = pygit2.Repository(str(repository_path))
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(f"Cannot open ledger repo: {exc}") from exc

    branch_ref = f"refs/heads/artifact/{request_id}"
    ref = repo.references.get(branch_ref)
    if ref is None:
        raise RuntimeError(
            f"Artifact branch '{branch_ref}' not found. Cannot witness."
        )
    tree = ref.peel().tree
    filename = f"{request_id}.md"
    try:
        blob = tree[filename]
    except KeyError as exc:
        raise RuntimeError(
            f"Artifact markdown '{filename}' not found in branch."
        ) from exc
    markdown_text = (repo[blob.id].data).decode("utf-8", errors="strict")

    from src.envelope_v2 import parse_artifact_markdown_text_v2

    envelope, body = parse_artifact_markdown_text_v2(markdown_text)
    if envelope.signature is None:
        raise RuntimeError("Cannot witness: artifact has no sealer signature.")

    # 2. Run full-chain verification — refuse to witness broken work.
    notary = CryptoNotaryAdapter(event_bus=runtime.event_bus, env_path=runtime.env_path)
    # Read the existing C2PA sidecar's hash from the branch (must match what
    # the sealer signed — rebuilding it fresh would produce different bytes).
    manifest_hash = None
    c2pa_sidecar_name = f"{request_id}.c2pa"
    try:
        c2pa_blob = tree[c2pa_sidecar_name]
        c2pa_bytes = bytes(repo[c2pa_blob.id].data)
        import hashlib as _hl

        manifest_hash = _hl.sha256(c2pa_bytes).hexdigest()
    except KeyError:
        pass  # no C2PA sidecar — manifest_hash stays None.
    try:
        verified = notary.verify_artifact_payload(
            envelope=envelope,
            payload=body,
            manifest_hash=manifest_hash,
        )
    except RuntimeError as exc:
        raise RuntimeError(
            f"Refusing to witness: artifact verification raised: {exc}"
        ) from exc
    if not verified:
        raise RuntimeError(
            "Refusing to witness: artifact signature verification FAILED. "
            "A witness is a vote of confidence — do not witness broken work."
        )
    print(f"Verification passed (existing {len(envelope.operator_seals)} seal(s)).")

    # 3. Load this operator's keys (already done by CryptoNotaryAdapter.__init__).
    if notary._private_key is None or notary._ed25519_private_key is None:
        raise RuntimeError(
            "Witness operator has no signing keys configured. "
            "Set PQC_PRIVATE_KEY_PATH and ED25519_PRIVATE_KEY_PATH."
        )

    # 4. Capture WebAuthn (operator presence check).
    webauthn_attestation = None
    if not getattr(args, "no_webauthn", False):
        _enforce_webauthn_rp_id_or_dev_run(runtime.env_path)
        from src.canonicalization import canonicalize_body_for_hash
        from src.webauthn_attestation import get_webauthn_assertion, get_webauthn_provider

        challenge_bytes = canonicalize_body_for_hash(body)
        challenge_hash = hashlib.sha256(challenge_bytes).digest()
        if get_webauthn_provider(env_path=runtime.env_path) == "platform":
            print("Opening browser for Touch ID attestation...")
        else:
            print("Insert your security key and touch it to complete attestation...")
        webauthn_attestation = get_webauthn_assertion(
            challenge=challenge_hash,
            repo_path=repository_path,
            env_path=runtime.env_path,
        )
        if webauthn_attestation is None:
            raise RuntimeError(
                "WebAuthn attestation required but not captured. Pass --no-webauthn to skip."
            )
        print("WebAuthn attestation captured.")

    # 5. Compute the witness seal over the same canonical target.
    payload_hash = envelope.signature.artifact_hash
    from src.adapters.c2pa_manifest import build_c2pa_sidecar_manifest

    c2pa_manifest = None
    if notary._enable_c2pa:
        try:
            c2pa_manifest = build_c2pa_sidecar_manifest(
                envelope, body, env_path=runtime.env_path
            )
        except Exception:
            c2pa_manifest = None  # best-effort; the sealer's C2PA is what matters.

    ceremony = _capture_registration_ceremony(runtime.env_path)
    witness_seal = notary.build_witness_seal(
        envelope=envelope,
        body=body,
        payload_hash=payload_hash,
        manifest_hash=(None if c2pa_manifest is None else c2pa_manifest.manifest_hash),
        ceremony=ceremony,
        webauthn_attestation=webauthn_attestation,
    )

    # 6. Append the witness seal to the envelope.
    updated_seals = list(envelope.operator_seals) + [witness_seal]
    updated_envelope = envelope.model_copy(update={"operator_seals": updated_seals})

    # 7. Re-render and commit to the same branch (append-only commit).
    from src.envelope_v2 import (
        EnvelopeSidecars,
        parse_sidecars_from_markdown,
        render_artifact_markdown_v2,
    )

    sidecars = parse_sidecars_from_markdown(markdown_text)
    rendered = render_artifact_markdown_v2(
        updated_envelope,
        body,
        ledger_request_id=request_id,
        sidecars=sidecars,
        env_path=runtime.env_path,
    )

    # Commit to the artifact branch via pygit2 (append-only).
    blob_id = repo.create_blob(rendered.encode("utf-8"))
    parent_commit = ref.peel()
    from pygit2 import Signature, TreeBuilder

    author = Signature(
        name="Antiphoria Slop Provenance",
        email="bot@antiphoria.local",
    )
    tb = repo.TreeBuilder(parent_commit.tree)
    tb.insert(filename, blob_id, 0o100644)
    new_tree = tb.write()
    commit_oid = repo.create_commit(
        branch_ref,
        author,
        author,
        f"provenance: witness seal by operator ({ceremony.operator_pseudonym_hash or 'unknown'})",
        new_tree,
        [parent_commit.id],
    )

    # 8. Update the catalog row's seal count.
    try:
        catalog_adapter = CatalogAdapter(
            repository_path=repository_path,
            env_path=runtime.env_path,
        )
        entries = catalog_adapter.read_entries()
        row = next(
            (e for e in entries if str(e.get("requestId")) == request_id),
            None,
        )
        if row is not None:
            row["operatorSealCount"] = len(updated_seals)
            row["operators"] = [
                (s.operator_pseudonym_hash or "unknown")[:16] for s in updated_seals
            ]
            catalog_adapter.upsert_entry(row)
    except Exception as exc:  # noqa: BLE001
        _cli_logger.warning("Catalog update after witness failed: %s", exc)

    print(
        f"Witness seal appended. {len(updated_seals)} total seal(s) on artifact {request_id}."
    )
    print(f"Commit: {commit_oid}")
    await runtime.event_bus.drain()
    return 0


def _resolve_revision_from_args(
    args: argparse.Namespace,
    repository_path: Path,
) -> Revision | None:
    """Build a Revision block from --supersedes/--reason/--note args, or None.

    Validation: --supersedes requires --reason (the category is mandatory). A
    missing prior artifact is a hard error (operator typo vs. deliberate action
    can't be told apart — fail loudly).
    """
    supersedes = getattr(args, "supersedes", None)
    if not supersedes:
        return None
    reason = getattr(args, "reason", None)
    if not reason:
        raise RuntimeError(
            "--supersedes requires --reason (why this version supersedes the prior)."
        )
    note = getattr(args, "note", None)
    return _resolve_prior_version_revision(
        repository_path=repository_path,
        supersedes_request_id=supersedes,
        reason=reason,
        note=note,
    )


def _resolve_prior_version_revision(
    repository_path: Path,
    supersedes_request_id: str,
    reason: str,
    note: str | None,
) -> Revision:
    """Resolve a Revision block from a prior artifact in the git archive.

    Reads the prior artifact's markdown from its ``artifact/<requestId>`` branch,
    extracts its ``payloadHash`` and ``revision`` (if any), and builds a new
    Revision pointing to it. Fails hard if the prior artifact can't be found or
    has no signed payload hash — supersession is a deliberate operator act, so
    a missing prior version is a hard error, not a silent skip.
    """
    import pygit2

    from src.models import Revision

    try:
        repo = pygit2.Repository(str(repository_path))
    except (KeyError, pygit2.GitError) as exc:
        raise RuntimeError(
            f"Cannot resolve prior version: ledger repo unreadable: {exc}"
        ) from exc

    branch_ref = f"refs/heads/artifact/{supersedes_request_id}"
    ref = repo.references.get(branch_ref)
    if ref is None:
        raise RuntimeError(
            f"Cannot supersede: prior artifact branch '{branch_ref}' not found."
        )
    tree = ref.peel().tree
    filename = f"{supersedes_request_id}.md"
    try:
        blob = tree[filename]
    except KeyError as exc:
        raise RuntimeError(
            f"Cannot supersede: prior artifact markdown '{filename}' not found in branch."
        ) from exc
    markdown = (repo[blob.id].data).decode("utf-8", errors="strict")

    from src.envelope_v2 import parse_artifact_markdown_text_v2

    try:
        prior_envelope, _ = parse_artifact_markdown_text_v2(markdown)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"Cannot supersede: prior artifact failed to parse: {exc}"
        ) from exc

    prior_sig = prior_envelope.signature
    if prior_sig is None or not prior_sig.artifact_hash:
        raise RuntimeError(
            "Cannot supersede: prior artifact has no signed payloadHash."
        )
    prior_payload_hash = prior_sig.artifact_hash

    # chainRoot: the v1 of this work. If the prior artifact was itself a
    # supersession, inherit its chainRoot; otherwise the prior is v1.
    if prior_envelope.revision is not None:
        chain_root = prior_envelope.revision.chain_root
        prior_sequence = prior_envelope.revision.sequence
    else:
        chain_root = supersedes_request_id
        prior_sequence = 1
    new_sequence = prior_sequence + 1

    return Revision(
        chainRoot=chain_root,
        sequence=new_sequence,
        supersedes=supersedes_request_id,
        supersedesHash=prior_payload_hash,
        reason=reason,  # type: ignore[arg-type]
        note=note,
    )


# v3 (Flaw B): the only RP ID an artifact may ship against. Credentials bind
# permanently to the RP ID used at registration, so this is an allowlist, not a
# blocklist — a typo'd domain would mint un-verifiable credentials just like
# localhost. Local experiments must set ANTIPHORIA_DEV_RUN=1.
_PRODUCTION_RP_IDS = frozenset({"antiphoria.org"})


def _enforce_webauthn_rp_id_or_dev_run(env_path: Any) -> None:
    """Flaw B guard (pre-release.md §3). Refuse to capture WebAuthn assertions
    unless ``WEBAUTHN_RP_ID`` is a recognised production domain, or the run is
    explicitly flagged throwaway via ``ANTIPHORIA_DEV_RUN=1``.

    WebAuthn binds a credential's ``rpIdHash`` to the RP ID used at registration
    forever. Sealing against ``localhost`` (or any non-production value) produces
    credentials that can never be verified against the production domain. The
    dev-run artifacts in the archive are already grandfathered as legacy; this
    guard prevents minting more. Applied to both seal/register pipelines and the
    one-time ``webauthn-register`` enrolment.
    """
    from src.env_config import read_env_bool, read_env_optional

    rp_id = read_env_optional("WEBAUTHN_RP_ID", env_path=env_path)
    is_dev_run = read_env_bool("ANTIPHORIA_DEV_RUN", env_path=env_path, default=False)
    if is_dev_run:
        return
    normalized = rp_id.strip().lower() if rp_id else ""
    if normalized not in _PRODUCTION_RP_IDS:
        allowed = ", ".join(sorted(_PRODUCTION_RP_IDS))
        raise RuntimeError(
            "WebAuthn capture refused: WEBAUTHN_RP_ID must be a production domain "
            f"({allowed}); got "
            f"{rp_id!r}. Credentials bind to the RP ID forever, so any other value "
            "(unset, 'localhost', or a typo) is permanently un-verifiable. Set "
            "WEBAUTHN_RP_ID and deploy the bridge page at "
            "https://antiphoria.org/bridge.html, or set ANTIPHORIA_DEV_RUN=1 to "
            "explicitly flag this as a throwaway dev run."
        )


def _derive_register_title(body: str, filename: str) -> str:
    """Derive artifact title from body or filename."""
    first_line = body.strip().splitlines()[0].strip() if body.strip() else ""
    candidate = first_line.strip("# ").strip()[:50]
    if candidate:
        return candidate
    return Path(filename).stem or "Untitled"


# Canonical self-declaration prompts for human registration. Stored verbatim in
# artifact frontmatter. Do not truncate or normalize.
_REGISTER_DISCLAIMER = (
    "This records your self-declaration. It is not notarization, copyright "
    "registration, or legal proof of authorship."
)
_REGISTER_QUESTION_1 = (
    "Do you state that you are a human acting on your own behalf, "
    "and that you are able to make these statements?"
)
_REGISTER_QUESTION_2 = (
    "Do you state that you are the author of this text and that it is your original work?"
)
_REGISTER_QUESTION_3_TEMPLATE = (
    "Do you state that this text is your independent work and that its content "
    "matches the {} classification you selected above?"
)
_REGISTER_QUESTION_4 = (
    "Do you understand that this statement will be cryptographically sealed into a "
    "public, append-only ledger, and that changing or removing it later would break "
    "the provenance chain?"
)


async def _run_register_command(args: argparse.Namespace) -> int:
    """Run human-only certification pipeline."""
    runtime = build_provenance_command_runtime(args, enforce_external_repo_path=True)
    event_bus = runtime.event_bus
    repository = runtime.repository
    telemetry_adapter = runtime.telemetry_adapter
    repository_path = runtime.repository_path
    provenance_service = runtime.provenance_service
    completion_future = create_story_committed_future()
    signed_by_request: dict[UUID, StorySigned] = {}

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
    from src.pseudonym import salt_appears_in_text

    if salt_appears_in_text(runtime.env_path, body):
        raise RuntimeError("Pseudonym salt detected in artifact body; publication blocked.")
    title = args.title or _derive_register_title(body, artifact_path.name)

    from src.runtime.stack_readiness import assert_ceremony_stack_ready

    require_webauthn = not getattr(args, "no_webauthn", False) and not getattr(
        args, "non_interactive", False
    )
    assert_ceremony_stack_ready(
        env_path=runtime.env_path,
        repository_path=repository_path,
        require_webauthn=require_webauthn,
    )

    # --- Self-declaration wizard ---
    if getattr(args, "non_interactive", False):
        attestation = AuthorAttestation(
            attestation_mode="unattended",
            attestations=[],
        )
    else:
        try:
            print("\n" + "=" * 50)
            print("SELF-DECLARATION WIZARD")
            print("=" * 50)
            print(_REGISTER_DISCLAIMER)
            print()
            print("STEP 1: Artistic Classification")
            print(
                "To establish the artistic context for this record, "
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

            print("\nSTEP 2: Self-Declaration Prompts")
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
                        "Registration aborted: All prompts must be agreed to (y) to proceed."
                    )

            attestation = AuthorAttestation(
                classification=classification,
                attestation_mode="interactive",
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
    if not getattr(args, "no_webauthn", False) and not getattr(args, "non_interactive", False):
        _enforce_webauthn_rp_id_or_dev_run(runtime.env_path)
        from src.canonicalization import canonicalize_body_for_hash
        from src.webauthn_attestation import get_webauthn_assertion, get_webauthn_provider

        challenge_bytes = canonicalize_body_for_hash(body)
        challenge_hash = hashlib.sha256(challenge_bytes).digest()
        if get_webauthn_provider(env_path=runtime.env_path) == "platform":
            print("Opening browser for Touch ID attestation...")
        else:
            print("Insert your security key and touch it to complete attestation...")
        webauthn_attestation = get_webauthn_assertion(
            challenge=challenge_hash,
            repo_path=repository_path,
            env_path=runtime.env_path,
        )
        if webauthn_attestation is None:
            raise RuntimeError(
                "WebAuthn attestation required but not captured. Run "
                "'slop-cli webauthn-register', set "
                "WEBAUTHN_RP_ID, approve Touch ID in the browser, or pass "
                "--no-webauthn for CI-only unattended paths."
            )
        print("WebAuthn attestation captured.")

    async def _record_signed(event: StorySigned) -> None:
        signed_by_request[event.request_id] = event
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
    revision = _resolve_revision_from_args(args, repository_path)
    human_event = StoryHumanRegistered(
        body=body,
        title=title,
        license=args.license,
        rights_holder=getattr(args, "author", None),
        revision=revision,
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
    await _maybe_upsert_catalog_after_commit(
        repository_path,
        runtime.env_path,
        committed_event,
        signed_by_request,
    )
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


# Orchestration declaration prompts for LLM-only sealing. Stored verbatim in
# artifact frontmatter. Do not truncate or normalize.
_SEAL_DISCLAIMER = (
    "This records your orchestration declaration. It is not proof of process "
    "lineage, notarization, or legal proof of authorship."
)
_SEAL_QUESTION_1 = (
    "Do you state that no human authored this text body, and that it was "
    "produced by machine generation?"
)
_SEAL_QUESTION_2 = (
    "Do you state that you acted as orchestrator only (prompting, selection, "
    "assembly — not composition)?"
)
_SEAL_QUESTION_3 = (
    "Do you state that any attached process description is a good-faith account "
    "and not verified lineage?"
)
_SEAL_QUESTION_4 = (
    "Do you understand that this will be sealed into a public, append-only ledger "
    "and dedicated to the public domain (CC0)?"
)


def _parse_models_list(raw: str | None) -> list[str]:
    """Parse comma-separated model identifiers from CLI input."""
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _load_process_narrative(process_file: Path) -> tuple[bytes, str]:
    """Wrap operator narrative JSON in the mandatory unverified envelope."""
    raw_text = process_file.read_text(encoding="utf-8").lstrip("\ufeff")
    try:
        loaded = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Process narrative file is not valid JSON: '{process_file}'.") from exc
    if not isinstance(loaded, dict):
        raise RuntimeError("Process narrative must be a JSON object.")
    wrapped = {
        "schemaVersion": "process-narrative.v1",
        "kind": "operator-narrative",
        "verified": False,
        "narrative": loaded,
    }
    narrative_bytes = canonical_json_bytes(wrapped)
    return narrative_bytes, sha256_hex(narrative_bytes)


async def _run_seal_command(args: argparse.Namespace) -> int:
    """Run LLM-only sealing pipeline with orchestration declaration."""
    runtime = build_provenance_command_runtime(args, enforce_external_repo_path=True)
    event_bus = runtime.event_bus
    repository = runtime.repository
    telemetry_adapter = runtime.telemetry_adapter
    repository_path = runtime.repository_path
    provenance_service = runtime.provenance_service
    completion_future = create_story_committed_future()
    signed_by_request: dict[UUID, StorySigned] = {}

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
                f"File has malformed frontmatter. For LLM-only sealing, "
                f"use plain markdown or fix the frontmatter: '{artifact_path}'."
            ) from None
    else:
        body = raw_text.strip()
    if not body:
        raise RuntimeError(f"File body is empty: '{artifact_path}'.")

    assert_secret_free("artifact body", body)
    from src.pseudonym import salt_appears_in_text

    if salt_appears_in_text(runtime.env_path, body):
        raise RuntimeError("Pseudonym salt detected in artifact body; publication blocked.")
    title = args.title or _derive_register_title(body, artifact_path.name)
    models_used = _parse_models_list(getattr(args, "models", None))

    process_narrative_bytes: bytes | None = None
    process_narrative_hash: str | None = None
    process_file = getattr(args, "process_file", None)
    if process_file:
        process_path = Path(process_file).resolve()
        if not process_path.exists():
            raise RuntimeError(f"Process narrative file not found: '{process_path}'.")
        process_narrative_bytes, process_narrative_hash = _load_process_narrative(process_path)

    from src.runtime.stack_readiness import assert_ceremony_stack_ready

    require_webauthn = not getattr(args, "no_webauthn", False) and not getattr(
        args, "non_interactive", False
    )
    assert_ceremony_stack_ready(
        env_path=runtime.env_path,
        repository_path=repository_path,
        require_webauthn=require_webauthn,
    )

    if getattr(args, "non_interactive", False):
        attestation = AuthorAttestation(
            attestation_nature="orchestration-declaration",
            attestation_mode="unattended",
            attestations=[],
        )
    else:
        try:
            print("\n" + "=" * 50)
            print("ORCHESTRATION DECLARATION WIZARD")
            print("=" * 50)
            print(_SEAL_DISCLAIMER)
            print()
            print("STEP 1: Artistic Classification")
            print(
                "To establish the artistic context for this record, "
                "how do you classify the primary intent of this text? Select one:"
            )
            print("[1] Statement of Fact / Record (Intended as literal truth)")
            print("[2] Opinion / Commentary (Subjective analysis or belief)")
            print("[3] Creative Fiction / Art (Imaginative or literary work)")
            print("[4] Satire / Parody (Humorous or exaggerated critique)")
            class_choice = input("Enter 1-4: ").strip()
            class_map = {"1": "fact", "2": "opinion", "3": "fiction", "4": "satire"}
            if class_choice not in class_map:
                raise RuntimeError("Sealing aborted: Invalid classification selected.")
            classification = class_map[class_choice]

            print("\nSTEP 2: Orchestration Declaration Prompts")
            questions = [
                _SEAL_QUESTION_1,
                _SEAL_QUESTION_2,
                _SEAL_QUESTION_3,
                _SEAL_QUESTION_4,
            ]
            answers: list[str] = []
            for i, q in enumerate(questions, 1):
                raw = input(f"Prompt {i}: {q} [y/N]: ").strip()
                answers.append(raw)
                if raw.lower() != "y":
                    raise RuntimeError(
                        "Sealing aborted: All prompts must be agreed to (y) to proceed."
                    )

            attestation = AuthorAttestation(
                attestation_nature="orchestration-declaration",
                classification=classification,
                attestation_mode="interactive",
                attestations=[
                    AttestationQa(question=q, answer=a)
                    for q, a in zip(questions, answers, strict=True)
                ],
            )
            print("=" * 50 + "\n")
        except (KeyboardInterrupt, EOFError):
            print("\nSealing aborted by user.")
            return 1

    webauthn_attestation = None
    if not getattr(args, "no_webauthn", False) and not getattr(args, "non_interactive", False):
        _enforce_webauthn_rp_id_or_dev_run(runtime.env_path)
        from src.canonicalization import canonicalize_body_for_hash
        from src.webauthn_attestation import get_webauthn_assertion, get_webauthn_provider

        challenge_bytes = canonicalize_body_for_hash(body)
        challenge_hash = hashlib.sha256(challenge_bytes).digest()
        if get_webauthn_provider(env_path=runtime.env_path) == "platform":
            print("Opening browser for Touch ID attestation...")
        else:
            print("Insert your security key and touch it to complete attestation...")
        webauthn_attestation = get_webauthn_assertion(
            challenge=challenge_hash,
            repo_path=repository_path,
            env_path=runtime.env_path,
        )
        if webauthn_attestation is None:
            raise RuntimeError(
                "WebAuthn attestation required but not captured. Run "
                "'slop-cli webauthn-register', set "
                "WEBAUTHN_RP_ID, approve Touch ID in the browser, or pass "
                "--no-webauthn for CI-only unattended paths."
            )
        print("WebAuthn attestation captured.")

    async def _record_signed(event: StorySigned) -> None:
        signed_by_request[event.request_id] = event
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
    revision = _resolve_revision_from_args(args, repository_path)
    sealed_event = StorySyntheticSealed(
        body=body,
        title=title,
        license=args.license,
        rights_holder=getattr(args, "author", None),
        revision=revision,
        models_used=models_used,
        attestation=attestation,
        webauthn_attestation=webauthn_attestation,
        registration_ceremony=ceremony,
        process_narrative_bytes=process_narrative_bytes,
        process_narrative_hash=process_narrative_hash,
    )

    if should_log_route("coarse"):
        _cli_logger.info(
            "command seal file=%s repo_path=%s",
            getattr(args, "file", "-"),
            getattr(args, "repo_path", None) or _default_repo_path(),
            extra={"command": "seal"},
        )

    await event_bus.subscribe(StorySigned, _record_signed)
    await event_bus.subscribe(StoryCommitted, _record_committed)
    await event_bus.subscribe_errors(build_dispatch_error_handler(completion_future))
    await telemetry_adapter.start()
    await notary_adapter.start()
    await ledger_adapter.start()

    bind_log_context(request_id=sealed_event.request_id)
    await event_bus.emit(sealed_event)
    committed_event = await asyncio.wait_for(completion_future, timeout=300.0)
    await _maybe_upsert_catalog_after_commit(
        repository_path,
        runtime.env_path,
        committed_event,
        signed_by_request,
    )
    await _anchor_and_timestamp_committed_artifact(
        event_bus=event_bus,
        provenance_service=provenance_service,
        repository_path=repository_path,
        committed_event=committed_event,
    )
    print(
        "Sealing completed:",
        f"request_id={sealed_event.request_id}",
        f"commit={committed_event.commit_oid}",
        f"path={committed_event.ledger_path}",
    )
    _print_attest_next_step(repository_path, sealed_event.request_id)
    await event_bus.drain()
    return 0
