# Limitations and design notes

This document complements the overview in the root [README.md](../README.md). It is not a substitute for [SECURITY.md](SECURITY.md) or legal/policy docs in this folder.

## Reproducibility and “truth”

- **Generative output** is not reproducible byte-for-byte across models, prompts, and runtimes. Provenance captures *what was claimed and signed*, not objective literary quality.
- **Multiple sources of truth** (local git ledger, optional remote transparency log, timestamps) can disagree; the tooling exposes those states for audit rather than silently picking one.

## Cryptography and formats

- **ML-DSA** signing is provided via `liboqs-python`; deployment must match supported platforms and library versions.
- **Hybrid signing** includes Ed25519 alongside ML-DSA; both key materials must be configured for generation/signing paths. See [QUICKSTART.md](QUICKSTART.md) Track A.
- **Canonical JSON** for signing uses JCS (RFC 8785). Older artifacts may not verify if they were produced under different canonicalization rules (see [SECURITY.md](SECURITY.md) remediation notes).

## C2PA modes

- **`C2PA_MODE=mvp`:** emits deterministic JSON sidecars intended for development and pipeline hooks. This is **not** the same as a full C2PA validator-grade signed manifest in the binary `c2pa` sense.
- **`C2PA_MODE=sdk`:** uses `c2pa-python` for signed binary sidecars; requires appropriate X.509 material and stricter configuration. Fail-closed behavior applies when sidecar generation fails.

## C2PA and markdown

In `sdk` mode, markdown is not always the direct signed C2PA “asset”; the pipeline may sign a derived payload (e.g. XML bridge) that binds to the markdown hash. See README “C2PA implementation note” for the intended binding.

## Horizontal scaling / multiple workers

Git ledger commits use **process-local** file locks. Multiple processes or hosts writing the same ledger repo without a **single-writer** or distributed lock strategy risk corruption. This repository focuses on local `slop-cli` execution; design multi-worker topologies accordingly.

## Operational

- **BYOV / vault** workflows are required for production-grade private key handling; dev keys on disk are explicitly discouraged for production (see [SECURITY.md](SECURITY.md)).
- **Windows native** development is best-effort; **WSL2** is the supported Windows path ([WSL2_SETUP.md](WSL2_SETUP.md)).
