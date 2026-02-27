# Slop Orchestrator

Event-driven provenance engine for short-story generation, cryptographic certification, and long-term auditability.

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

## Environment

Create `.env` in the project root:

```dotenv
GOOGLE_API_KEY=...
PQC_PRIVATE_KEY_PATH=./keys/private.pem
OQS_PUBLIC_KEY_PATH=./keys/public.pem
SIGNER_FINGERPRINT=optional-fingerprint
TRANSPARENCY_LOG_PUBLISH_URL=https://example.org/transparency/append
RFC3161_TSA_URL=https://freetsa.org/tsr
RFC3161_CA_CERT_PATH=./keys/tsa-ca.pem
SIGNING_KEY_VERSION=v1
```

Only the key and API entries are strictly required for generation/signature flow. TSA and transparency publish URL are optional but recommended for long-term external auditability.

## Core Commands

### Generate and certify

```bash
slop-cli generate --prompt "A short brutalist micro-story." --repo-path ../my-ledger
```

### Curate and re-certify

```bash
slop-cli curate --file ../my-ledger/artifacts/<request_id>.md --repo-path ../my-ledger
```

### Signature verification

```bash
slop-cli verify --file ../my-ledger/artifacts/<request_id>.md
```

### Explicit anchoring

```bash
slop-cli anchor --file ../my-ledger/artifacts/<request_id>.md --repo-path ../my-ledger
```

### RFC3161 timestamp

```bash
slop-cli timestamp --file ../my-ledger/artifacts/<request_id>.md --repo-path ../my-ledger --tsa-url https://freetsa.org/tsr --tsa-ca-cert-path ./keys/tsa-ca.pem
```

### Full-chain audit report

```bash
slop-cli audit --file ../my-ledger/artifacts/<request_id>.md --repo-path ../my-ledger --tsa-ca-cert-path ./keys/tsa-ca.pem --report-file ./audit_report.json
```

## Repository Policies

- Code license: Apache-2.0 (`LICENSE`)
- Legal disclaimers: `DISCLAIMER.md`
- Terms of use: `TERMS_OF_USE.md`
- Content licensing strategy: `CONTENT_LICENSE_POLICY.md`
- Operational key policy: `KEY_MANAGEMENT_POLICY.md`
- Retention and continuity policy: `PROVENANCE_RETENTION_POLICY.md`
