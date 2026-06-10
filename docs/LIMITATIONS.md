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

## C2PA modes

- **`C2PA_MODE=mvp`:** emits deterministic JSON sidecars intended for development and pipeline hooks. This is **not** the same as a full C2PA validator-grade signed manifest in the binary `c2pa` sense.
- **`C2PA_MODE=sdk`:** uses `c2pa-python` for signed binary sidecars; requires appropriate X.509 material and stricter configuration. Fail-closed behavior applies when sidecar generation fails.

## C2PA and markdown

In `sdk` mode, markdown is not always the direct signed C2PA “asset”; the pipeline may sign a derived payload (e.g. XML bridge) that binds to the markdown hash. See README “C2PA implementation note” for the intended binding.

## Horizontal scaling / multiple workers

Git ledger commits use **process-local** file locks. Multiple processes or hosts writing the same ledger repo without a **single-writer** or distributed lock strategy risk corruption. This repository focuses on local `slop-cli` execution; design multi-worker topologies accordingly.

## Human registration and personhood metadata

- **Self-declaration** (wizard Q&A when run interactively) records what the operator stated at signing time; it is not independent proof of authorship, notarization, or copyright registration.
- **`attestationNature: self-declaration`** and **`attestationMode`** (`interactive` vs `unattended`) are embedded in artifact frontmatter so third parties can see how the record was captured.
- **`--non-interactive`:** skips the wizard and records `attestationMode: unattended` with no Q&A pairs and `classification: null`. Suitable for CI, not operator self-declaration.
- **WebAuthn** (`attestationStrength: webauthn`) binds a platform or roaming authenticator assertion to the artifact body hash. The engine **embeds** assertion metadata; it does not currently **verify** WebAuthn assertions in `verify` / `attest` (treat as experimental provenance, not a legal identity guarantee).
- **Platform provider (macOS Touch ID):** uses a short-lived `127.0.0.1` browser bridge with per-ceremony token auth. Credentials are bound to `localhost` RP ID—not a production web domain.
- **HID provider (USB FIDO2):** requires `pip install -e ".[webauthn]"` and a connected security key.
- **Operator pseudonym** (`operatorPseudonymHash`): HMAC-derived from a secret salt you control. Proves continuity across artifacts registered with the same salt; reveals no device data. Losing the salt breaks continuity; leaking it lets others impersonate that pseudonym. Prefer this over `CAPTURE_MACHINE_ID` (MAC hash), which remains opt-in and off by default.
- **`--non-interactive` / `--no-webauthn`:** unattended or self-declaration-only paths; suitable for CI, not maximum personhood metadata.

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

- **BYOV / vault** workflows are required for production-grade private key handling; dev keys on disk are explicitly discouraged for production (see [SECURITY.md](../SECURITY.md)).
- **Windows native** development is best-effort; **WSL2** is the supported Windows path ([WSL2_SETUP.md](WSL2_SETUP.md)).
