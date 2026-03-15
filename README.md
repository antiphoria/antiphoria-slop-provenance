# Slop Orchestrator

Event-driven provenance engine for short-story generation, cryptographic certification, and long-term auditability.

> **Privacy warning:** All prompts are cryptographically sealed into artifacts. Do not include PII, confidential data, or trade secrets in your prompts—they cannot be un-published once signed and committed.

## What it does

- Generates stories from prompts using Gemini.
- Signs artifacts with ML-DSA (`liboqs`).
- Commits signed markdown artifacts into a git ledger.
- Anchors artifact hashes into an append-only transparency log.
- Requests RFC3161 trusted timestamps for anchored artifacts.
- Produces machine-readable provenance audit reports.

## Installation

```bash
pip install -e .
```

**Windows users:** The project depends on `liboqs-python`, OpenSSL, and `make`, which are painful to set up natively on Windows. See [doc/WSL2_SETUP.md](doc/WSL2_SETUP.md) for a WSL2 + Docker Desktop setup tutorial.

## Environment

Copy the example environment file and fill in your values. **Never commit `.env`**—it contains secrets.

**Unix / macOS / Git Bash:**

```bash
cp .env.example .env
```

**PowerShell:**

```powershell
Copy-Item .env.example .env
```

Edit `.env` and set at least:

```dotenv
GOOGLE_API_KEY=...
GENERATOR_MODEL_ID=gemini-2.5-flash
GENERATOR_DUMMY_MODE=false
GENERATOR_DUMMY_DELAY_SEC=1.0
OQS_PUBLIC_KEY_PATH=./keys/public.key
SIGNER_FINGERPRINT=optional-fingerprint
TRANSPARENCY_LOG_PUBLISH_URL=https://example.org/transparency/append
RFC3161_TSA_URL=https://freetsa.org/tsr
RFC3161_CA_CERT_PATH=./keys/tsa-ca.pem
RFC3161_TSA_UNTRUSTED_CERT_PATH=./keys/tsa.crt
SIGNING_KEY_VERSION=v1
STATE_DB_PATH=./state.db
ENABLE_C2PA=false
C2PA_MODE=mvp
```

When using the secure launcher (`run-secure.ps1` / `run-secure.sh`), `PQC_PRIVATE_KEY_PATH` and `C2PA_PRIVATE_KEY_PATH` are injected by the launcher—do not add them to `.env`. For dev with keys on disk, set them manually.

Only the key and API entries are strictly required for generation/signature flow. TSA and transparency publish URL are optional but recommended for long-term external auditability.

**Supabase requirement:** If `TRANSPARENCY_LOG_PUBLISH_URL` is set, you *must* also set either `SUPABASE_SERVICE_KEY` or `SUPABASE_ANON_KEY`. Attestation cannot validate against the remote transparency log without these keys; the CLI will fail at startup if the URL is set but keys are missing.

For quota-free local pipeline testing, set `GENERATOR_DUMMY_MODE=true` (and
optionally `GENERATOR_DUMMY_DELAY_SEC=0`). In dummy mode, `GOOGLE_API_KEY` is
not required and no network call to Gemini is made.

If RFC3161 verification fails because OpenSSL cannot locate its config on
Windows/conda installs, you can optionally set:

```dotenv
OPENSSL_BIN=openssl
OPENSSL_CONF=C:/path/to/openssl.cnf
```

For OpenTimestamps Bitcoin anchoring, set `ENABLE_OTS_FORGE=true` in `.env`
and install the optional dependency: `pip install -e ".[ots]"`.

## Secure key handling (BYOV)

For production, use the BYOV (Bring Your Own Vault) flow so private keys never touch disk at runtime. See [SECURITY.md](SECURITY.md) for the full threat model and procedures.

**Bootstrap:** Run `python scripts/gen-mldsa-keys.py`; run `./scripts/gen-c2pa-keys.ps1` (Windows) or `./scripts/gen-c2pa-keys.sh` (Linux); then create the vault and populate it per SECURITY.md.

**Runtime:** Use the launcher to run commands with keys injected from the vault:

```bash
# Windows (PowerShell as Administrator)
./run-secure.ps1 slop-cli generate --prompt "A short brutalist micro-story." --repo-path ../my-ledger

# Linux
./run-secure.sh slop-cli generate --prompt "A short brutalist micro-story." --repo-path ../my-ledger
```

## Core Commands

### Generate and certify

```bash
slop-cli generate --prompt "A short brutalist micro-story." --repo-path ../my-ledger
```

The command prints a follow-up attestation command when generation completes.
Run that command directly (no manual branch checkout required):

```bash
slop-cli attest --repo-path ../my-ledger --request-id <request_id>
```

### Curate and re-certify

```bash
slop-cli curate --file ../my-ledger/<request_id>.md --repo-path ../my-ledger
```

Human-only registration:

```bash
slop-cli register --file ../my-ledger/human-story.md --repo-path ../my-ledger --non-interactive
```

### Request-ID attestation (recommended)

```bash
slop-cli attest --repo-path ../my-ledger --request-id <request_id>
```

Strict mode requires a valid RFC3161 timestamp, otherwise attestation fails:

```bash
slop-cli attest --repo-path ../my-ledger --request-id <request_id> --strict
```

JSON output for automation/CI:

```bash
slop-cli attest --repo-path ../my-ledger --request-id <request_id> --json
```

### Signature verification

```bash
slop-cli verify --file ../my-ledger/<request_id>.md
```

### Explicit anchoring

```bash
slop-cli anchor --file ../my-ledger/<request_id>.md --repo-path ../my-ledger
```

### RFC3161 timestamp

```bash
slop-cli timestamp --file ../my-ledger/<request_id>.md --repo-path ../my-ledger --tsa-url https://freetsa.org/tsr --tsa-ca-cert-path ./keys/tsa-ca.pem
```

### Full-chain audit report

```bash
slop-cli audit --file ../my-ledger/<request_id>.md --repo-path ../my-ledger --tsa-ca-cert-path ./keys/tsa-ca.pem --report-file ./audit_report.json
```

Kafka orchestration (distributed workers) lives in a separate repository. This certification engine exposes only `slop-cli` for local execution.

## C2PA implementation note

When `ENABLE_C2PA=true`, the pipeline emits `.c2pa` sidecar payloads and binds their hash
into the canonical ML-DSA signing target (`manifestHash`).

- `C2PA_MODE=mvp` writes deterministic JSON sidecars for legacy/dev compatibility (not C2PA-signed manifests; see [doc/LIMITATIONS.md](doc/LIMITATIONS.md)).
- `C2PA_MODE=sdk` uses `c2pa-python` to emit signed binary sidecars intended for
  validator-grade interoperability.

In `sdk` mode, markdown is not signed directly as the C2PA source asset. Instead, the
pipeline builds a deterministic XML bridge payload from envelope metadata plus markdown
`payloadSha256`, and signs that XML payload to produce the detached `.c2pa` sidecar.

`sdk` mode requires X.509 signer material. The cert chain stays on disk; the private key is injected by the run-secure launcher when using BYOV:

```dotenv
C2PA_SIGN_CERT_CHAIN_PATH=./keys/c2pa-cert-chain.pem
C2PA_SIGNING_ALG=ES256
```

When `ENABLE_C2PA=true` and `C2PA_MODE=sdk`, sidecar generation is fail-closed: if C2PA
sidecar creation fails, notarization aborts and no artifact commit is produced.

Strict C2PA checks are available in verification and attestation commands:

```bash
slop-cli verify --file ../my-ledger/<request_id>.md --strict-c2pa
slop-cli attest --repo-path ../my-ledger --request-id <request_id> --strict-c2pa
slop-cli audit --file ../my-ledger/<request_id>.md --repo-path ../my-ledger --strict-c2pa
```

## Developer shortcuts

```bash
make install
make hooks
make lint
make test
make compile
make requirements   # Regenerate requirements.txt from requirements.in (for Docker)
make metrics
make down
```

`make hooks` installs the local pre-commit guardrails (Ruff + secret scan + hygiene checks).
Any high-confidence secret detection blocks the commit.

Worker services write per-service metric snapshots into `.metrics/` by default.
You can print a consolidated report with:

```bash
slop-metrics --metrics-dir ./.metrics
slop-metrics --metrics-dir ./.metrics --json
```

## Limitations and design notes

See [doc/LIMITATIONS.md](doc/LIMITATIONS.md) for scientific, design, and enterprise limitations (reproducibility, mixed sources of truth, C2PA MVP mode, etc.).

## Repository Policies

- Code license: Apache-2.0 (`LICENSE`)
- Legal disclaimers: `DISCLAIMER.md`
- Terms of use: `TERMS_OF_USE.md`
- Content licensing strategy: `CONTENT_LICENSE_POLICY.md`
- Operational key policy: `KEY_MANAGEMENT_POLICY.md`
- Retention and continuity policy: `PROVENANCE_RETENTION_POLICY.md`
