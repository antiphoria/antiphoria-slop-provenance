# Antiphoria Slop Provenance

[![CI Lint](https://github.com/antiphoria/antiphoria-slop-provenance/actions/workflows/ci-lint.yml/badge.svg)](https://github.com/antiphoria/antiphoria-slop-provenance/actions/workflows/ci-lint.yml)
[![CI Tests](https://github.com/antiphoria/antiphoria-slop-provenance/actions/workflows/ci-tests.yml/badge.svg)](https://github.com/antiphoria/antiphoria-slop-provenance/actions/workflows/ci-tests.yml)
[![CI Trivy](https://github.com/antiphoria/antiphoria-slop-provenance/actions/workflows/ci-trivy.yml/badge.svg)](https://github.com/antiphoria/antiphoria-slop-provenance/actions/workflows/ci-trivy.yml)
[![Gitleaks](https://github.com/antiphoria/antiphoria-slop-provenance/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/antiphoria/antiphoria-slop-provenance/actions/workflows/gitleaks.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/antiphoria/antiphoria-slop-provenance/badge)](https://securityscorecards.dev/viewer/?uri=github.com/antiphoria/antiphoria-slop-provenance)

This project is **research and artistic exploration**: technical experiments in provenance, signing, and ledgers. It is **not** a legal, regulatory, or commercial certification service. Signatures and metadata are **technical records** for transparency and audit—they are not determinations of law, platform compliance, or third-party rights.

The software must be used in a **research setting only** and **for artistic purposes**. On first CLI use you are prompted to confirm (or set `ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK=1` for non-interactive use after reading the terms).

**Human-only registration** records **what the operator self-attests at signing time**; it does not independently prove human authorship to others.

Use of this software is subject to [docs/TERMS_OF_USE.md](docs/TERMS_OF_USE.md) and [docs/DISCLAIMER.md](docs/DISCLAIMER.md).

> **Privacy warning:** All prompts are cryptographically sealed into artifacts. Do not include PII, confidential data, or trade secrets in your prompts—they cannot be un-published once signed and committed.

## Quick path for new users

**Start here:** [docs/QUICKSTART.md](docs/QUICKSTART.md) — clone, `uv sync --extra dev` (or `pip install -e ".[dev]"`), `.env` (including a **dummy-mode** track with no Gemini/Supabase), `pytest`, and `slop-cli`.

**Windows:** Prefer **WSL2**; see [docs/WSL2_SETUP.md](docs/WSL2_SETUP.md).

## What it does

- Generates stories from prompts using Gemini (or **dummy mode** for local testing).
- Signs artifacts with ML-DSA (`liboqs`) and Ed25519.
- Commits signed markdown artifacts into a git ledger.
- Optionally anchors artifact hashes into a transparency log and requests RFC3161 timestamps.
- Supports human-only registration with optional WebAuthn (Touch ID / FIDO2) and operator pseudonym continuity.
- Produces machine-readable provenance audit reports.

## Installation

Use **Python 3.12** in a **repo-local venv** (see [docs/QUICKSTART.md](docs/QUICKSTART.md)); that matches CI and avoids relying on a global `python` that may be the wrong version or missing wheels (e.g. `pygit2`).

Dependencies are locked in **`uv.lock`**. Recommended install ([uv](https://docs.astral.sh/uv/)):

```bash
uv sync --extra dev
```

Alternative (editable install from `pyproject.toml`, e.g. org CI):

```bash
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Runtime-only (no test extras): `uv sync` or `pip install -e .`

Optional OpenTimestamps: `pip install -e ".[ots]"`

Optional WebAuthn (USB FIDO2 or macOS Touch ID bridge): `pip install -e ".[webauthn]"`

## Environment

Copy [`.env.example`](.env.example) to `.env` and edit. **Never commit `.env`.** Variable meanings and optional sections are commented in `.env.example`.

**Summary:**

- **Track A (synthetic sealing):** `slop-cli seal --file <body.md> --models <m1>,<m2>` — no API key required (the engine seals operator-supplied LLM output, it does not call a generator).
- **Track B (human registration):** `slop-cli register --file <body.md>` — operator self-declares human authorship.
- **Transparency log:** local-only in v3 (Supabase remote publication removed); Bitcoin via OTS is the only remote anchor.

**Production keys:** use BYOV and the secure launchers — [SECURITY.md](SECURITY.md).

```bash
# Windows (PowerShell as Administrator)
./scripts/run-secure.ps1 slop-cli generate --prompt "A short brutalist micro-story." --repo-path ../my-ledger

# Linux
./scripts/run-secure.sh slop-cli generate --prompt "A short brutalist micro-story." --repo-path ../my-ledger
```

With keys on disk for development only, set `PQC_PRIVATE_KEY_PATH`, `OQS_PUBLIC_KEY_PATH`, and Ed25519 paths in `.env` as described in [docs/QUICKSTART.md](docs/QUICKSTART.md).

## Core Commands

### Generate and certify

```bash
slop-cli generate --prompt "A short brutalist micro-story." --repo-path ../my-ledger
```

The command prints a follow-up attestation command when generation completes.

```bash
slop-cli attest --repo-path ../my-ledger --request-id <request_id>
```

### Curate and re-certify

```bash
slop-cli curate --file ../my-ledger/<request_id>.md --repo-path ../my-ledger
```

### Human-only registration

Register self-declared human markdown (no AI generation). Interactive mode runs a self-declaration wizard; optional Touch ID / FIDO2 WebAuthn and operator pseudonym continuity are configured in `.env`. See [docs/QUICKSTART.md](docs/QUICKSTART.md) Track C.

```bash
# One-time Touch ID / passkey enrollment (macOS platform provider)
slop-cli webauthn-register --repo-path ../my-ledger

# Register plain markdown (interactive wizard + optional WebAuthn)
slop-cli register --file ../my-ledger/human-story.md --repo-path ../my-ledger
```

CI / automation (skips wizard; no Q&A captured, `attestationMode: unattended`):

```bash
slop-cli register --file ../my-ledger/human-story.md --repo-path ../my-ledger --non-interactive
```

Skip WebAuthn only: add `--no-webauthn`.

### Seal LLM-only content

Seal externally produced machine text with an orchestration declaration (human orchestrator, not author). Default license is CC0-1.0. Use a separate ledger repo from human-only `register` artifacts when publishing to an LLM research journal.

```bash
# Seal with interactive orchestration declaration wizard
slop-cli seal --file ../my-ledger/llm-research.md --repo-path ../my-ledger-llm

# Optional: attach unverified process narrative (stored as {request_id}.process.json)
slop-cli seal \
  --file ../my-ledger/llm-research.md \
  --process-file ./run-narrative.json \
  --models gemini-3.1-pro,composer-2.5 \
  --repo-path ../my-ledger-llm
```

CI / automation (skips wizard; `provenanceGrade: unattended`):

```bash
slop-cli seal --file ../my-ledger/llm-research.md --repo-path ../my-ledger-llm --non-interactive
```

### Strict attestation (RFC3161)

```bash
slop-cli attest --repo-path ../my-ledger --request-id <request_id> --strict
```

### JSON output

```bash
slop-cli attest --repo-path ../my-ledger --request-id <request_id> --json
```

### Verify

```bash
slop-cli verify --file ../my-ledger/<request_id>.md
```

### Anchor / timestamp / audit

```bash
slop-cli anchor --file ../my-ledger/<request_id>.md --repo-path ../my-ledger
slop-cli timestamp --file ../my-ledger/<request_id>.md --repo-path ../my-ledger --tsa-url https://freetsa.org/tsr --tsa-ca-cert-path ./keys/tsa-ca.pem
slop-cli audit --file ../my-ledger/<request_id>.md --repo-path ../my-ledger --tsa-ca-cert-path ./keys/tsa-ca.pem --report-file ./audit_report.json
```

### Catalog (human lookup index)

The archive stores a derived catalog at `.provenance/catalog.jsonl` on `main`. It is updated automatically after each commit and can be rebuilt from artifact branches.

```bash
slop-cli catalog list --repo-path ../my-ledger
slop-cli catalog list --repo-path ../my-ledger --source human --limit 20
slop-cli catalog show --repo-path ../my-ledger --request-id <request_id>
slop-cli catalog index --repo-path ../my-ledger
```

## C2PA

When `ENABLE_C2PA=true`, the pipeline emits `.c2pa` sidecars and binds their hash into the ML-DSA signing target. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for MVP vs SDK mode and design caveats.

```bash
slop-cli verify --file ../my-ledger/<request_id>.md --strict-c2pa
slop-cli attest --repo-path ../my-ledger --request-id <request_id> --strict-c2pa
```

## Developer shortcuts

```bash
make install    # uv sync --extra dev
make lint       # ruff check + format --check
make test       # pytest -v
make compile    # python -m compileall src
make lock       # uv lock (after changing pyproject.toml deps)
```

Optional: `ruff check .` and `ruff format .` if Ruff is installed.

## Limitations

[docs/LIMITATIONS.md](docs/LIMITATIONS.md)

## Repository policies

- Code license: Apache-2.0 ([LICENSE](LICENSE))
- [docs/DISCLAIMER.md](docs/DISCLAIMER.md)
- [docs/TERMS_OF_USE.md](docs/TERMS_OF_USE.md)
- [docs/CONTENT_LICENSE_POLICY.md](docs/CONTENT_LICENSE_POLICY.md)
- [docs/KEY_MANAGEMENT_POLICY.md](docs/KEY_MANAGEMENT_POLICY.md)
- [SECURITY.md](SECURITY.md)
