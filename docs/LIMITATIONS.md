# Limitations and design notes

This software must be used in a research setting only.

This document complements the overview in the root [README.md](../README.md). It is not a substitute for [SECURITY.md](../SECURITY.md) or legal/policy docs in this folder.

## Reproducibility and “truth”

- **Generative output** is not reproducible byte-for-byte across models, prompts, and runtimes. Provenance captures *what was claimed and signed*, not objective literary quality.
- **Multiple sources of truth** (local git ledger, optional remote transparency log, timestamps) can disagree; the tooling exposes those states for audit rather than silently picking one.

## Cryptography and formats

- **ML-DSA** signing is provided via `liboqs-python`; deployment must match supported platforms and library versions.
- **Hybrid signing** includes Ed25519 alongside ML-DSA; both key materials must be configured for generation/signing paths. See [QUICKSTART.md](QUICKSTART.md) Track A.
- **Canonical JSON** for signing uses JCS (RFC 8785). Older artifacts may not verify if they were produced under different canonicalization rules (see [SECURITY.md](../SECURITY.md) remediation notes).

## C2PA mode (v3)

- **SDK only.** MVP (unsigned JSON) mode was removed in v3 — it produced a sidecar
  that looked like C2PA but was signed by nobody, which is metadata theater. The
  `c2pa-python` SDK path is now the only mode. It requires X.509 material and
  uses fail-closed behavior when sidecar generation fails. See `pre-release.md §1`.

## C2PA and markdown

In `sdk` mode, markdown is not always the direct signed C2PA “asset”; the pipeline may sign a derived payload (e.g. XML bridge) that binds to the markdown hash. See README “C2PA implementation note” for the intended binding.

## Horizontal scaling / multiple workers

Git ledger commits use **process-local** file locks. Multiple processes or hosts writing the same ledger repo without a **single-writer** or distributed lock strategy risk corruption. This repository focuses on local `slop-cli` execution; design multi-worker topologies accordingly.

## Human registration and personhood metadata

- **Self-declaration** (wizard Q&A in `claim.statements`) records what the operator stated at signing time; it is not independent proof of authorship, notarization, or copyright registration.
- **`attestationStrength`** describes the **hardware trust layer only**: `webauthn` (assertion captured), `none` (explicit `--no-webauthn`), or `unattended` (`--non-interactive`). It does not measure declaration quality — use `claim.provenanceGrade` for that.
- **`operator.webauthn`** (v2 wire) carries the FIDO assertion metadata separately from the public declaration in `claim`.
- **`--non-interactive`:** skips the wizard and records `attestationMode: unattended` with no Q&A pairs and `classification: null`. Suitable for CI, not operator self-declaration.
- **WebAuthn** binds a platform or roaming authenticator assertion to the artifact body hash. The engine **embeds** assertion metadata in `operator.webauthn`; it does not currently **verify** WebAuthn assertions in `verify` / `attest` (treat as experimental provenance, not a legal identity guarantee). `--strict` attest requires the block to be **present** on interactive artifacts.
- **Platform provider (macOS Touch ID):** runs the ceremony on the hosted page `https://antiphoria.org/bridge.html` (so the page origin matches the RP ID) and posts the result back to a short-lived, loopback-only `127.0.0.1` bridge with per-ceremony token auth. Credentials bind to the production RP ID (`WEBAUTHN_RP_ID=antiphoria.org`). Credentials minted against `localhost` by older builds are permanently un-verifiable and must be re-enrolled.
- **HID provider (USB FIDO2):** requires `pip install -e ".[webauthn]"` and a connected security key.
- **Operator pseudonym** (`operatorPseudonymHash`): HMAC-derived from a secret salt you control. Proves continuity across artifacts registered with the same salt; reveals no device data. Losing the salt breaks continuity; leaking it lets others impersonate that pseudonym. Prefer this over `CAPTURE_MACHINE_ID` (MAC hash), which remains opt-in and off by default.
- **`--non-interactive` / `--no-webauthn`:** explicit CI escape hatches only; default interactive register/seal requires the full stack and aborts on missing layers.

## Provenance grades

| Grade | Meaning | Typical path |
|-------|---------|--------------|
| `recorded` | Process captured at creation time in the pipeline | `generate`, `curate` |
| `declared` | Operator declaration at seal time; process narrative optional and unverified | `register`, `seal` (interactive) |
| `unattended` | No operator ceremony captured | `--non-interactive` on `register` or `seal` |

Grades are stored as `provenanceGrade` in artifact frontmatter. They describe epistemic strength, not legal certification.

## LLM-only sealing (`seal`)

- **Orchestration declaration** (wizard Q&A when run interactively) records that the operator disclaims authorship of the text body and acted as orchestrator only; it is not proof of process lineage.
- **`attestationNature: orchestration-declaration`** distinguishes LLM sealing from human `self-declaration`.
- Default license is **CC0-1.0** (`source: synthetic`). Use `--models` to list models used; a single model becomes `modelId`, multiple become `composite` with full list in `modelsUsed`.
- **`--process-file`:** optional JSON wrapped in a mandatory sidecar envelope (`verified: false`, `kind: operator-narrative`) and committed as `{request_id}.process.json`. The hash is sealed in frontmatter as `processNarrativeHash`; the narrative is a good-faith account, never verified lineage.
- **`--non-interactive`:** skips the wizard and records `attestationMode: unattended`, `classification: null`, `provenanceGrade: unattended`.

## Operational

- **Archive catalog** (`.provenance/catalog.jsonl` on `main`) is a derived human lookup index, not part of the signed evidence chain. Rebuild with `slop-cli catalog index` from `artifact/*` branches if it drifts.
- **BYOV / vault** workflows are required for production-grade private key handling; dev keys on disk are explicitly discouraged for production (see [SECURITY.md](../SECURITY.md)).
- **Windows native** development is best-effort; **WSL2** is the supported Windows path ([WSL2_SETUP.md](WSL2_SETUP.md)).
