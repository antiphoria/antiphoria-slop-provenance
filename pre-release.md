# pre-release.md — v3 working checklist

Working checklist for bringing `antiphoria-slop-provenance` to its next coherent state (internally: **v3**). This document is the contract I execute against. Every item is anchored to specific files/lines so "done" is unambiguous.

**Read `user-stories.md` first.** That document defines *what the system is* (roles, flows, data shapes). This document defines *the work to get there*. If the two disagree, `user-stories.md` wins.

Status legend: `[ ]` pending · `[~]` in progress · `[x]` done · `[!]` blocked

---

## 0. Governing principles (apply to every decision)

From `user-stories.md §1`, restated briefly:

1. **Trust boundary is reputational.** "Human" = "Antiphoria warrants it." No metadata theater.
2. **Antiphoria does not hold the license. The author does.** → Flaw F.
3. **Hackerist.** Self-host, own the root, shed the vendor.
4. **Simplicity.** Delete over refactor.
5. **Maximum cryptographic redundancy, cleanly separated.** Each layer hedges a *distinct* failure mode; layers fail soft.
6. **Install or move on — for Operators.** Writers send text; they never install.
7. **Two roles: Writer (sends text) and Operator (seals + witnesses, full stack).**

---

## 1. v3 scope: what stays vs. what's safe-deleted

### Stays (the working core — verbatim, with surgical fixes)

- `canonicalization.py` — correct, non-obvious, keep as-is.
- `build_envelope_signing_target` + signing-relevant types in `models.py` — correct construction (signature fields excluded from signed bytes, JCS via `rfc8785`). Keep.
- `crypto_notary.py` dual ML-DSA-44 + Ed25519 sign/verify — keep, **strip to register/seal/witness only** (see safe-delete), **generalized to N seals** (Gap 2).
- `envelope_v2.py` → renamed conceptually to v3 wire codec — keep, becomes the *only* wire codec.
- `transparency_log.py` — keep, **Supabase code removed**.
- `ots_adapter.py`, `rfc3161_tsa.py`, `c2pa_manifest.py` (SDK path only) — keep.
- `git_ledger.py` topology — keep.
- `pseudonym.py` — keep.
- `webauthn_attestation.py`, `webauthn_bridge.py` — keep, **add real verification** (Flaw A).
- The test suite — keep, update for v3 wire format.

### Safe-delete (doesn't serve register/seal/witness/version)

- [ ] **`generate` command + `GeminiEngineAdapter`** — different product (AI generation). Delete `_run_generate_command` (`pipeline.py:174`), the adapter, the `StoryRequested`/`StoryGenerated` events (`events.py:33,44`), parser entries, CLI dispatch rows, related tests.
- [ ] **`curate` command + `curation_service.py`** — wrong model (mutates in place, invalidates anchors). Delete `_run_curate_command` (`pipeline.py:284`), `services/curation_service.py`, `StoryCurated` (`events.py:139`), `_on_story_curated` in `crypto_notary.py`. Replaced by versioning (Gap 1).
- [ ] **`antiphoria_sdk/` (the parallel `SealEngine`)** — separate crypto stack, "bridgeable but unused." Delete the whole directory. If we ever want a seal-chain, we derive it from the real envelope, not a parallel format.
- [ ] **`MvpC2PAManifestProvider`** (`c2pa_manifest.py:136`) — unsigned JSON masquerading as C2PA. Delete the class, the `"mvp"` mode literal, `resolve_c2pa_mode`, and the `C2PA_MODE` env var. SDK becomes the only mode.
- [ ] **`hybrid` content class + `source="hybrid"` paths** — only ever reachable via `curate`, which is going away. Collapse the enum to `human | synthetic`.
- [ ] **Supabase remote transparency-log code** (OD-3 — dropped) — corporate dep, conflicts with hackerist principle. Delete `build_supabase_publish_config`, `publish_merkle_anchor`, `update_merkle_anchor_block_height`, the Supabase-format branch in `_publish_entry`, `fetch_remote_entries_by_artifact_hash`, `_verify_remote_anchor` (in `verification_service.py`), and the `SUPABASE_*` env vars. Bitcoin (OTS) is the only remote trust root.
- [ ] **`example_text_llm_provenance.json`** + the standalone `artifact_zero.txt` anti-example clutter at repo root.
- [ ] **v1 wire format** (`render_artifact_markdown`, the v1 branch in `parsing.py:61`, the v1 `Artifact.schema_version: Literal["eternity.v1"]` at `models.py:224`). v3 becomes the only wire format. The two existing dev-run artifacts are grandfathered as legacy input only; they parse but new seals emit v3 exclusively.
- [ ] **`prevHash` in `build_envelope_signing_target`** (OD-2 — removed). Drop the parameter and the always-`None` call site. Work-versioning is handled by the signed `revision` block (Gap 1), which is a content commitment, not a verification dependency.

**Safe-delete discipline:** each deletion lands as its own commit with `git rm` + test updates, so the diff is auditable and reversible. No "big bang" deletion commit.

---

## 2. Flaws → concrete fixes

### Flaw A — WebAuthn captured but never verified `[ ]`

**Problem:** `--strict` attest checks `webauthn_present = envelope.provenance.webauthn_attestation is not None` (`verification_service.py:457`). No code path calls FIDO verify. The captured `signature`, `authenticatorData`, `clientDataJsonHash` are never checked. `public_key_cose_b64` is saved at enrollment (`webauthn_attestation.py:231`) and never read back.

**Role under v3:** Operator *presence* check — hedges "the sealing process was hijacked by malware on the Operator's machine." Not author identity (writers don't sign). Still meaningful; still worth fixing.

**Decision: verify for real.** Justification by principles:
- *Hackerist:* ES256 verification uses `cryptography` (already a dep, pure-wheel). No corporate.
- *Simplicity:* ~100–150 LOC.
- *Redundancy:* WebAuthn becomes a real layer (Layer 3 in `user-stories.md §3`), not theater.
- *User stories:* every Operator seal should carry a verifiable presence check.

**Fix shape:**
- [ ] Add `verify_webauthn_assertion(attestation, expected_rp_id, credential_public_key_cose) -> bool` to `webauthn_attestation.py`. Checks:
  - Decode `authenticatorData` → verify `rpIdHash == SHA-256(rp_id)`, `userPresent` flag set, `userVerified` flag set.
  - Verify the ES256 signature over `authenticatorData || SHA-256(clientDataJSON)` using the COSE public key.
  - Verify `clientDataJSON.type == "webauthn"`, `clientDataJSON.origin` matches RP ID origin, and **`clientDataJSON.challenge == base64url(expected_challenge_hash)`** where `expected_challenge_hash = SHA-256(canonical_body)`. This requires storing the full `clientDataJSON`, not just its hash.
- [ ] Add `client_data_json` field to `WebAuthnAttestation` model (`models.py:115`). v3 envelope renders/parses it.
- [ ] Publish `public_key_cose_b64` in the registry keyed by `credentialId` (see `user-stories.md §7.2`).
- [ ] Wire `verify_webauthn_assertion` into `_build_audit_report` and `_attestation_verdict`. Replace `webauthn_present` with `webauthn_verified` (bool). `--strict` now requires `webauthn_verified`, not presence.
- [ ] Rename the `AuditReport` field and the verdict printout. UI badge: "WebAuthn verified" (green) or "WebAuthn captured (unverified)" (amber), never silent green.

**Affected files:** `webauthn_attestation.py`, `models.py`, `envelope_v2.py` (v3 render/parse of `client_data_json`), `verification_service.py`, `commands/verification.py`, `web-ui/packages/antiphoria-verify/src/{verdict,envelope}.ts`, `registry.json`.

### Flaw B — `WEBAUTHN_RP_ID=localhost` in production `.env` `[x]`

**Problem:** `.env` and `.env.example` both have `WEBAUTHN_RP_ID=localhost`. The 2 existing dev-run artifacts are sealed against localhost and permanently unverifiable against any production RP ID. `webauthn_attestation.py:5–8` documents the landmine; the code ships it anyway.

**Decision: wait for `antiphoria.org` to resolve.** The dev-run artifacts are throwaway; sealing more localhost artifacts just creates more permanent garbage. The Flaw A code is RP-ID-agnostic; only runtime config changes when the domain resolves.

**Fix shape:**
- [x] `.env.example` and `.env` now set `WEBAUTHN_RP_ID=antiphoria.org` (no `localhost` default).
- [x] `_enforce_webauthn_rp_id_or_dev_run` (`commands/pipeline.py`) refuses to capture WebAuthn unless `WEBAUTHN_RP_ID` is in the production allowlist (`{antiphoria.org}`) or `ANTIPHORIA_DEV_RUN=1`. Now applied to `webauthn-register` enrolment too (`commands/maintenance.py`), not just seal/register.
- [x] Platform ceremony moved to the hosted page `https://antiphoria.org/bridge.html` (`public/bridge.html` in the org site); `webauthn_bridge.py` is now an API-only loopback callback server, binds credentials to the env RP ID, and persists `rp_id` accordingly. `verify_webauthn_assertion` origin check hardened against lookalike domains.
- [ ] **Deploy + re-enroll (manual gate):** publish `bridge.html` to Codeberg Pages, confirm `https://antiphoria.org/bridge.html` returns 200, delete the old `.webauthn-credentials.json` + macOS passkey, run `slop-cli webauthn-register`, and confirm the stored credential records `"rp_id": "antiphoria.org"`. Dev-run artifacts stay grandfathered as "legacy/unverified presence".

**Blocked on:** only the deploy + re-enrollment step remains; all code changes have landed.

### Flaw C — `verify --allow-redacted` trusts the envelope's claimed hash `[ ]`

**Problem:** `crypto_notary.py:675` — when `allow_redacted=True`, `payload_hash = envelope.signature.artifact_hash`. The signature over the hash is doing no work; the verifier confirms a tautology. Reports `[OK] REDACTED: Metadata and signatures valid.`

**Decision: relabel honestly, keep the path.** Redaction has a legit use (publish metadata without body); the fix is to stop calling it verified.

**Fix shape:**
- [ ] Change `[OK]` → `[INFO]` and message to: `REDACTED: metadata internally consistent. Signature cannot be checked — body absent. Reveal full body to verify.`
- [ ] Exit code stays 0 (intentional operator choice, not failure), but output must not contain "VERIFIED" or "valid."
- [ ] Update `tests/e2e/test_cli_local.py:354` (`test_redact_and_verify_allow_redacted`) for the new wording.

**Affected files:** `commands/verification.py:52–57`, the e2e test.

### Flaw D — C2PA embeds `eternity.v1` while markdown says v2 `[ ]`

**Problem:** `models.py:224` pins `schema_version: Literal["eternity.v1"]`. `_build_slop_orchestrator_context` (`c2pa_manifest.py:67`) writes `envelope.schema_version` into the C2PA assertion → always v1, contradicting the markdown header.

**Decision: thread v3 through.**

**Fix shape:**
- [ ] Change `Artifact.schema_version` to `Literal["eternity.v3"]`.
- [ ] Set `SCHEMA_VERSION_V3 = "eternity.v3"` in `envelope_v2.py`.
- [ ] Update `_validate_v2_invariants` (`envelope_v2.py:186`) to require `schemaVersion: eternity.v3`.
- [ ] All render paths emit v3; parse paths accept v3 and grandfather-read v2 for the dev-run artifacts.

**Affected files:** `models.py:224`, `envelope_v2.py`, `c2pa_manifest.py:67`, tests.

### Flaw E — Signing fingerprint derived from private key `[ ]`

**Problem:** `crypto_notary.py:232–243` — when `SIGNER_FINGERPRINT` env is empty (it is, in both `.env` and `.env.example`), the fallback is `sha256_hex(self._private_key)[:32]`. The published `registry.json` ML-DSA tier then has `fingerprint=77cfb75a...` but `publicKeySha256=0be3dec3...` — they don't match, because the fingerprint came from the private key. A third-party verifier cannot recompute the fingerprint from public material.

**Decision: derive from public key only.**

**Fix shape:**
- [ ] Change `_resolve_signer_fingerprint` fallback to derive from the *public* key: `sha256_hex(public_key_bytes)[:32]`. Requires loading the public key (already resolved via `_resolve_public_key`).
- [ ] Set `SIGNER_FINGERPRINT` explicitly in `.env` to the public-key-derived value, or leave unset and let the new fallback compute it.
- [ ] Regenerate `registry.json` so `fingerprint == publicKeySha256[:32]` for both tiers.
- [ ] Add a test asserting `fingerprint == sha256(public_key)[:32]`.

**Affected files:** `crypto_notary.py:232–243`, `.env.example`, `registry.json`, tests.

### Flaw F — License misattributed to Antiphoria `[ ]` *(new — from `user-stories.md §8`)*

**Problem:** `src/policies/license_text.py` hardcodes `_PUBLISHER = "antiphoria"` and emits e.g. `© 2026 antiphoria. All Rights Reserved.` as the `rights.statement` for *every* sealed human artifact. This is a legal misattribution: Antiphoria is claiming copyright on work that belongs to the author. Violates principle 2.

**Decision: the author is the rights holder.**

**Fix shape:**
- [ ] `rights.holder` becomes a required v3 field, populated from the author declaration (pen name or legal name).
- [ ] `LicenseText` templates substitute `{holder}` for the hardcoded publisher.
- [ ] `register` CLI gains `--author "<pen name>"` (required) and uses it for both `author.penName` and `rights.holder`.
- [ ] The dev-run artifact `af19b5fa-...` (sealed with `© 2026 antiphoria`) is a known-bad legacy; v3 sealing never emits this shape again.

**Affected files:** `policies/license_text.py`, `envelope_v2.py` (render/parse `rights.holder` + new `author` block), `commands/pipeline.py` (`register`/`seal`), `commands/parser/pipeline.py` (new `--author` flag), tests.

---

## 3. Product gaps → features

### Gap 1 — Versioning / supersession `[ ]`

**Problem:** No `supersedes`/`chainRoot` field. Re-registering a corrected text produces an unrelated artifact. Human works are immovable (the operator promises as much in `_REGISTER_QUESTION_4`), locking out legitimate copyright/plagiarism/error fixes.

**Decision: supersede, don't mutate. Append-only, new artifact, declared link.** See `user-stories.md §4` (Story 1.4) for the flow.

**Fix shape:**
- [ ] Add `revision` block to the v3 envelope (`user-stories.md §7.1`):
  ```yaml
  revision:                                # absent on first version
    chainRoot: "<requestId of v1>"
    sequence: 2
    supersedes: "<requestId of v1>"
    supersedesHash: "<payloadHash of v1>"   # content commitment, NOT a dependency
    reason: "copyright-flag | error-correction | plagiarism-removal | editorial | other"
    note: "<free text>"
  ```
- [ ] The block is inside `build_envelope_signing_target`'s `envelope` dict → covered by every operator seal automatically.
- [ ] Catalog gains `chainRoot`, `sequence`, `supersedes`, `supersededBy` fields. `supersededBy` on v1's row is filled when v2 is indexed (v1 itself never changes).
- [ ] New CLI flag: `slop-cli register --file ... --supersedes <requestId> --reason <reason> [--note "..."]`. Resolves the prior artifact's `payloadHash` from the archive, embeds it as `supersedesHash`.
- [ ] `--strict` attest on a superseded artifact warns "superseded by <requestId>" but still passes (the artifact is honest, just no longer current).

**Affected files:** `models.py` (new `Revision` model), `envelope_v2.py`, `build_envelope_signing_target`, `commands/pipeline.py` (new flag), `commands/parser/pipeline.py`, `adapters/catalog.py`, `verification_service.py` (warn on supersession), tests.

### Gap 2 (replaced) — Multi-operator witnessing `[ ]`

**Problem:** Today every artifact has exactly one trust root: the sealing operator's keypair. If that vault is compromised or the operator is coerced, every artifact they sealed is forgeable. **No layer hedges operator compromise.** This is the one failure mode the current stack has no answer for.

**Decision: Option A — true symmetric `operatorSeals[]`. (Operator decision, replacing the earlier Option B proposal.)**

The envelope is generalized from singular `signature`/`hybridSignature` to `operatorSeals: list[OperatorSeal]`. Every seal has identical anatomy; behavior is governed by the `role` string value (`sealer` | `witness`), not by schema placement. This is the only design that:
- keeps one unified verification loop (not two parallel paths),
- allows future roles (auditor, ombudsman) without schema changes,
- and breaks the wire format now — when only 2 dev-run artifacts exist — rather than after production scale.

**Wire-format change:** `Artifact.signature` and `Artifact.hybridSignature` are removed; `Artifact.operator_seals: list[OperatorSeal]` (min 1) replaces them. `Provenance.registration_ceremony`, `Provenance.webauthn_attestation`, and `Provenance.attestation_strength` move into `OperatorSeal` (each seal is self-contained). Legacy v2 artifacts parse via a 10-line grandfather filter in `parsing.py` that maps the old singular fields into a single `operatorSeals[]` entry with `role="sealer"`.

**Signing target (JCS canonicalization):** `build_envelope_signing_target` strips `cryptographicSignature` from every `operatorSeals[].primary` and `.hybrid` block while leaving all other metadata (pseudonymHash, role, ceremony, webauthn, algorithm, signerFingerprint, artifactHash) intact. Every operator independently signs identical canonical bytes; seals are order-independent and verify independently.

**Justification by principles:**
- *Hackerist:* no token, no consensus network, no new vendor. Git is the coordination layer; the "blockchain" is commit history + `operatorSeals[]`.
- *Simplicity:* one new CLI command (`witness`), one new envelope section (`operatorSeals[]`), one new transparency event. Crypto unchanged, applied N times.
- *Maximum redundancy, cleanly separated:* Layer 6 in `user-stories.md §3`. Hedges "operator compromised or coerced" — a failure mode *no other layer covers*. Collusion of *all* witnessing operators is the only way past it.
- *User stories:* the most important scaling axis (`user-stories.md §6`, §9).

**Fix shape:**
- [ ] Generalize the envelope from a single `signature`/`hybrid_signature` to `operatorSeals[]` (`user-stories.md §7.1`). Each entry: `{operatorPseudonymHash, role: "sealer"|"witness", sealedAt, ceremony, primary, hybrid}`.
- [ ] Each seal signs the *same canonical target* (envelope with all `operatorSeals[].primary/hybrid.signature` fields excluded, plus payload hash). N operators each independently sign identical bytes; seals don't depend on each other.
- [ ] New CLI: `slop-cli witness --request-id <id> --repo-path <archive>`. The witnessing operator:
  1. Loads the sealed artifact.
  2. Runs **full-chain verification** — refuses to witness anything broken. (A witness is a vote of confidence; witnessing broken work destroys the witness's credibility.)
  3. Loads their own keys (different vault, different pseudonym).
  4. Computes a fresh ML-DSA-44 + Ed25519 seal over the same canonical target.
  5. Appends to `operatorSeals[]`.
  6. Commits the augmented envelope (append-only — original seal never touched).
  7. Logs a transparency entry under their pseudonym.
- [ ] Catalog gains `operatorSealCount` and `operators[]` fields for queryability.
- [ ] `verify`/`attest` resolve every `operatorSeals[]` entry against the registry and verify each independently.
- [ ] Concurrent witnessing: standard git merge (entries are independent, order-independent). `[OD-US-3]` — start with merge, add lock only if conflicts prove painful.

**Affected files:** `models.py` (new `OperatorSeal` model; deprecate singular `signature`/`hybrid_signature`), `envelope_v2.py`, `build_envelope_signing_target` (exclude all seals), `crypto_notary.py` (sign → emit `OperatorSeal`; generalize verify), `commands/pipeline.py` (`register`/`seal` emit a single-entry `operatorSeals[]`), new `commands/witness.py` (or a `_run_witness_command` in `pipeline.py`), `verification_service.py`, `adapters/catalog.py`, `adapters/key_registry.py`, `registry.json`, tests.

**`[OD-US-4]` — witnessing for both profiles or human-only?** Tentative: both. Confirm before implementing.

### Gap 3 — Human works excluded from revision `[x]` (resolved by Gap 1)

Once versioning lands, the `curate`-mediated in-place mutation path is gone (safe-deleted, §1) and the supersede path is open to all profiles. No separate work item.

### Gap 4 — Split install for writers `[x]` (resolved — not needed)

Under the converged model (`user-stories.md §2`), writers never install. They send text. No `sign` CLI, no browser WebAuthn for writers, no `collect-attestation`. This entire gap is dissolved; nothing to build.

### Gap 5 — `curate` mutates row + branch `[x]` (resolved — safe-deleted, §1)

### Gap 6 — Process narrative has no version link `[x]` (resolved by Gap 1)

The process narrative sidecar is hashed and signed as part of the envelope. When the envelope is superseded, the new envelope's `synthesis.processNarrative.contentHash` reflects the new narrative. No separate work item.

### Gap 7 — Hybrid signature not persisted in SQLite `[ ]`

`artifact_records` stores `cryptographic_signature` (primary ML-DSA) only. The hybrid Ed25519 lives only in the markdown + git branch. Under v3 + witnessing, this becomes "store the full `operatorSeals[]` serialized."

**Fix shape:**
- [ ] Replace the singular `cryptographic_signature` column with `operator_seals_json` (the full `operatorSeals[]` array serialized).
- [ ] Persist in `create_artifact_record` and on each witness event.
- [ ] Migration for existing dev-run rows (read from markdown; null/empty is fine for legacy).

**Affected files:** `repository/types.py`, `repository/stores/artifact_store.py`, `repository/sqlite.py` (schema migration), `pipeline.py` callers, the new `witness` command.

---

## 4. Open decisions (resolved)

**OD-1 — ML-DSA-44: mandatory.** Two signatures always. liboqs stays a hard dep. The dual-sig is the core hedge against algorithm breakage; the project is hackerist, install cost is acceptable for the few trusted Operators. Install friction is handled by keeping the Operator population small (§0), not by weakening per-artifact guarantees.

**OD-2 — `prevHash` removed.** The stub is gone. Work-versioning is handled by the signed `revision` block (Gap 1), which is a content commitment, not a verification dependency.

**OD-3 — Remote transparency-log mirror dropped.** Supabase code goes (§1 safe-delete). No replacement. Bitcoin (OTS) is the only remote anchor; RFC3161 + local log + Bitcoin is three distinct trust roots. A self-hosted static JSONL mirror is documented as a future option if Bitcoin confirmation latency ever bites a real use case.

**Role model — two roles.** Writer (sends text, installs nothing) and Operator (seals + witnesses, full stack). Recorded in `user-stories.md §2`. The earlier three-role and Author-as-collaborator models are superseded.

---

## 5. Sequencing

Dependencies, not arbitrary order:

```
Phase 0 (now, unblocked):
  ├─ Safe-deletes (§1): generate, curate, antiphoria_sdk/, MVP C2PA, Supabase, v1 wire, prevHash
  ├─ Flaw D (v3 schema_version bump) — with the wire format consolidation
  ├─ Flaw E (fingerprint from public key)
  ├─ Flaw F (license owner = author)              ← NEW
  ├─ Flaw C (redact relabel)
  └─ Gap 7 prep (schema migration plan; full landing waits on Gap 2 shape)

Phase 1 (WebAuthn decision, mostly unblocked):
  ├─ Flaw A (real verification + clientDataJson storage)
  └─ Flaw B code changes (RP ID guard, .env.example) — re-enroll waits on domain

Phase 2 (product shape):
  ├─ Gap 1 (versioning) — depends on Phase 0 wire format settled
  └─ Gap 2 (witnessing) — depends on Flaw A (real presence verification)

Phase 3 (when antiphoria.org resolves):
  └─ Flaw B completion: re-enroll, set prod RP ID, grandfather dev artifacts
```

Each phase is independently shippable. Phase 0 alone produces a cleaner, smaller, legally-correct, more honest codebase.

---

## 6. Definition of done (per item)

Each fix/feature is "done" when:

- [ ] Code change landed, with the affected files from each section updated.
- [ ] Tests added or updated; `make test` (or equivalent) passes.
- [ ] If the change affects the wire format, the v3 spec section in `spec_doc_and_vision.md` is updated to match `user-stories.md §7`.
- [ ] If the change affects operator-facing behavior, `.env.example` and relevant `docs/` are updated.
- [ ] If the change affects what the UI renders, `web-ui` is updated in the same PR (or a tracked follow-up).
- [ ] The commit message references the Flaw/Gap ID (e.g., `fix(flaw-f): author holds license, not antiphoria`).

---

## 7. What this checklist does NOT do

- Does not build a Writer submission surface. That's transport (email today), decided when a real Writer arrives (`OD-US-1`).
- Does not migrate to a new repo. Extraction is deferred until a trigger fires (real Writer data, or slop-provenance genuinely can't absorb another feature — neither is true today).
- Does not add new cryptographic algorithms. Maximalism is expressed through witnessing (Gap 2), not more sig schemes.
- Does not touch the legal/domain situation. Flaw B's code changes land now; re-enrollment waits.
- Does not build writer-facing signing, browser WebAuthn for writers, `collaborators[]` per-author attestation, or a pure-decentralized DAG. All explicitly out of scope for v3 (`user-stories.md §12`).
