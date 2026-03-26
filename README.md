# Antiphoria Slop Provenance

Event-driven provenance engine for short-story generation, cryptographic signing and provenance, and long-term auditability.

This project is **research and artistic exploration**: technical experiments in provenance, signing, and ledgers. It is **not** a legal, regulatory, or commercial certification service. Signatures and metadata are **technical records** for transparency and audit—they are not determinations of law, platform compliance, or third-party rights.

The software must be used in a **research setting only** and **for artistic purposes**. On first CLI use you are prompted to confirm (or set `ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK=1` for non-interactive use after reading the terms).

**Human-only registration** records **what the operator self-attests at signing time**; it does not independently prove human authorship to others.

Use of this software is subject to [docs/TERMS_OF_USE.md](docs/TERMS_OF_USE.md) and [docs/DISCLAIMER.md](docs/DISCLAIMER.md).

> **Privacy warning:** All prompts are cryptographically sealed into artifacts. Do not include PII, confidential data, or trade secrets in your prompts—they cannot be un-published once signed and committed.

## Quick path for new users

**Start here:** [docs/QUICKSTART.md](docs/QUICKSTART.md) — clone, `pip install -e ".[dev]"`, `.env` (including a **dummy-mode** track with no Gemini/Supabase), `pytest`, and `slop-cli`.

**Windows:** Prefer **WSL2**; see [docs/WSL2_SETUP.md](docs/WSL2_SETUP.md).

## What it does

- Generates stories from prompts using Gemini (or **dummy mode** for local testing).
- Signs artifacts with ML-DSA (`liboqs`) and Ed25519.
- Commits signed markdown artifacts into a git ledger.
- Optionally anchors artifact hashes into a transparency log and requests RFC3161 timestamps.
- Produces machine-readable provenance audit reports.

## Installation

Use **Python 3.12** in a **repo-local venv** (see [docs/QUICKSTART.md](docs/QUICKSTART.md)); that matches CI and avoids relying on a global `python` that may be the wrong version or missing wheels (e.g. `pygit2`).

```bash
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Runtime-only (no test extras): `pip install -e .`

Optional OpenTimestamps: `pip install -e ".[ots]"`

## Environment

Copy [`.env.example`](.env.example) to `.env` and edit. **Never commit `.env`.** Variable meanings and optional sections are commented in `.env.example`.

**Summary:**

- **Dummy / local testing:** set `GENERATOR_DUMMY_MODE=true` — no `GOOGLE_API_KEY` required.
- **Live generation:** set `GOOGLE_API_KEY` and `GENERATOR_DUMMY_MODE=false`.
- **Transparency log:** if `TRANSPARENCY_LOG_PUBLISH_URL` is set, you must set `SUPABASE_SERVICE_KEY` or `SUPABASE_ANON_KEY`.
- **Worker dedup DB (advanced):** optional `STATE_DB_PATH`; default state layout uses `ORCHESTRATOR_STATE_DIR` (see `src/env_config.py`).

**Production keys:** use BYOV and the secure launchers — [docs/SECURITY.md](docs/SECURITY.md).

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

```bash
slop-cli register --file ../my-ledger/human-story.md --repo-path ../my-ledger --non-interactive
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

## C2PA

When `ENABLE_C2PA=true`, the pipeline emits `.c2pa` sidecars and binds their hash into the ML-DSA signing target. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for MVP vs SDK mode and design caveats.

```bash
slop-cli verify --file ../my-ledger/<request_id>.md --strict-c2pa
slop-cli attest --repo-path ../my-ledger --request-id <request_id> --strict-c2pa
```

## Developer shortcuts

```bash
make install    # pip install -e ".[dev]"
make lint       # ruff check + format --check
make test       # pytest -v
make compile    # python -m compileall src
make requirements   # regenerate requirements.txt from requirements.in
make metrics
```

Optional: `ruff check .` and `ruff format .` if Ruff is installed.

Worker services can write metric snapshots under `.metrics/`:

```bash
slop-metrics --metrics-dir ./.metrics
slop-metrics --metrics-dir ./.metrics --json
```

## Limitations

[docs/LIMITATIONS.md](docs/LIMITATIONS.md)

## Repository policies

- Code license: Apache-2.0 ([LICENSE](LICENSE))
- [docs/DISCLAIMER.md](docs/DISCLAIMER.md)
- [docs/TERMS_OF_USE.md](docs/TERMS_OF_USE.md)
- [docs/CONTENT_LICENSE_POLICY.md](docs/CONTENT_LICENSE_POLICY.md)
- [docs/KEY_MANAGEMENT_POLICY.md](docs/KEY_MANAGEMENT_POLICY.md)
- [docs/SECURITY.md](docs/SECURITY.md)
