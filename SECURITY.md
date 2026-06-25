The software must be used in a research setting only.

Most parts of this software were vibecoded and audited by LLMs with little human oversight.

# Security: Key Handling (BYOV)

## Security Audit Remediation (Breaking Changes)

The following changes were made to address cryptographic and integrity vulnerabilities. **Existing artifacts and transparency logs may be incompatible.**

- **Merkle tree:** RFC 6962-style domain separation (leaf vs internal node hashing) and odd-node promotion (no duplication). Merkle roots will change. `verify_merkle_proof` now accepts optional `tree_size` for odd-sized trees.
- **Null bytes:** Artifacts containing `\x00` are rejected (no longer stripped). Invalid payloads raise `RuntimeError`.
- **JSON canonicalization:** `canonical_json_bytes` now uses RFC 8785 (JCS). Existing signatures may break if the previous output differed from JCS.
- **Path traversal:** `tree_get_blob` rejects `..`, `.`, and absolute paths with `ValueError`.

## Subprocess usage and automated scanners

Tools such as **Python Code Audit** often flag every `subprocess.run` or `os.access` call. In this project:

- **No shell** is used for those calls: arguments are passed as a **list** (`argv`), not a single string interpreted by `/bin/sh`, which avoids the usual command-injection class when combined with static subcommands (`git rev-parse`, `openssl ts`, `ots stamp`, etc.).
- **`OPENSSL_BIN`** and **`OTS_BIN`** are **operator trust boundaries**: they must point at the real OpenSSL and OpenTimestamps CLI binaries. The application does not execute arbitrary user-provided command lines.
- **`os.access(..., X_OK)`** on the bundled `bin/ots` (Unix) is an **advisory** chmod hint for developers, not an access-control or security gate.
- **Base64** in the codebase is used for **binary encoding** (signatures, RFC3161 tokens, OTS proofs), not for confidentiality or "hiding" secrets.

Re-run static analysis after refactors; many findings are **false positives** (e.g. regexes that redact `Bearer` / `apikey` in logs, or the string `secret` in error messages).

## Threat Model

Private keys (ML-DSA `private.key`, C2PA `c2pa-private-key.pem`, and Ed25519 `ed25519_private.pem`) and the **operator pseudonym salt** (`pseudonym.salt`) must never be written to disk at runtime except on encrypted vault storage. The BYOV (Bring Your Own Vault) architecture ensures **zero-disk-exposure**: keys are provided via secure, volatile mounts. The application receives paths to keys in RAM or on a temporarily mounted volume; when the process exits, the launcher unmounts or deletes the volatile storage.

## Bootstrap Flow

1. **Generate ML-DSA keys:** `python scripts/gen-mldsa-keys.py`
2. **Generate C2PA keys:** `./scripts/gen-c2pa-keys.ps1` (Windows) or `./scripts/gen-c2pa-keys.sh` (Linux)
3. **Generate Ed25519 keys:** `python scripts/gen-ed25519-keys.py`
4. **Move `c2pa-root-ca.key.pem` to offline USB** (never store on disk with other keys)
5. **Create vault manually** (see below)
6. **Generate operator pseudonym salt (optional):** `python scripts/gen-pseudonym-salt.py --out /path/to/vault/pseudonym.salt`
7. **SECURE CLEANUP:** Delete `keys/private.key`, `keys/c2pa-private-key.pem`, `keys/ed25519_private.pem`, and any repo-local `pseudonym.salt` from disk after populating the vault.
8. **Keep `public.key`, `c2pa-cert-chain.pem`, and `ed25519_public.pem` on disk**; reference via `.env` (`OQS_PUBLIC_KEY_PATH`, `C2PA_SIGN_CERT_CHAIN_PATH`, `ED25519_PUBLIC_KEY_PATH`). Set `OPERATOR_PSEUDONYM_SALT_PATH` to the vault copy of `pseudonym.salt`.

## Manual Vault Creation

### Windows (VeraCrypt)

Scripting VeraCrypt container creation via CLI is brittle across Windows builds. Use a 100% manual flow:

1. Open VeraCrypt
2. Click **Create Volume** → choose **Standard** volume
3. Select path: `keys_vault.hc` (project root)
4. Choose size (e.g. 10 MB)
5. Set a strong password
6. Format as **FAT32**
7. Mount the new volume, copy `private.key`, `c2pa-private-key.pem`, `ed25519_private.pem`, and optionally `pseudonym.salt` from `keys/` or vault path into it
8. Unmount
9. **SECURE CLEANUP:** Delete `keys/private.key`, `keys/c2pa-private-key.pem`, and `keys/ed25519_private.pem` from your SSD.

### Linux (GPG)

From project root:

```bash
tar cf keys_vault.tar -C keys private.key c2pa-private-key.pem ed25519_private.pem
# Optional: add pseudonym.salt to the archive if generated
gpg -c keys_vault.tar
rm keys/private.key keys/c2pa-private-key.pem keys/ed25519_private.pem
```

This produces `keys_vault.tar.gpg`. The `rm` step removes the plaintext originals from disk. The archive is flat so `scripts/run-secure.sh` finds files at `$RAMDIR/private.key`, `$RAMDIR/c2pa-private-key.pem`, and `$RAMDIR/ed25519_private.pem`.

## Runtime Flow

Use the launcher to mount/extract the vault, inject key paths, run the app, and clean up:

- **Windows:** `./scripts/run-secure.ps1 slop-cli generate --prompt "..." --repo-path <path>`
- **Linux:** `./scripts/run-secure.sh slop-cli generate --prompt "..." --repo-path <path>`

If no arguments are passed, the launcher starts an interactive shell with the environment variables set.

## Windows UAC

Virtual volume mounting requires **Administrator privileges**. Run PowerShell as Administrator before invoking `scripts/run-secure.ps1` (or the script will exit with an error). If the session is elevated, the mounted drive may be in the Administrator context; `EnableLinkedConnections` can affect visibility across user contexts.

## Multi-Process (Windows)

If the vault is already mounted (e.g. notary in one terminal), a second `scripts/run-secure.ps1` detects it, reuses the drive, injects env, runs the child, and does **not** unmount. The first session unmounts when done.

## WebAuthn bridge (macOS Touch ID)

When `WEBAUTHN_PROVIDER=platform`, `register` and `webauthn-register` run the ceremony on a **hosted static page** served from the production origin (`https://antiphoria.org/bridge.html`) so credentials bind to the production RP ID (`WEBAUTHN_RP_ID=antiphoria.org`) and are verifiable. The CLI starts a **short-lived, loopback-only** HTTP server (`127.0.0.1`) that exposes a single `POST /callback` endpoint and shuts down after completion. Do not expose this port beyond loopback.

Design and controls:

- **Token never leaks to the page host.** The per-ceremony token (`secrets.token_urlsafe(32)`) and ceremony parameters are passed in the URL **fragment** (`#...`), which browsers never send to the host server, never store in shareable history/sync, and strip from `Referer`. The page reads them from `location.hash` (the same approach as OAuth implicit flow).
- **Result transport is a top-level form POST navigation**, not `fetch()`. This avoids HTTPS→`http://localhost` mixed-content blocking (which is unreliable in Safari) and needs no CORS.
- **Callback hardening:** Host-header validation (anti-DNS-rebinding), `hmac.compare_digest` token check, a required and bounded `Content-Length` (≤ 64 KiB), and a confused-deputy guard that rejects results whose shape does not match the requested ceremony mode.
- **Bridge page CSP** pins the inline script by SHA-256 hash (no `unsafe-inline`), reads input only via `textContent`/form `value` (no `innerHTML`), and restricts `form-action` to loopback. `WEBAUTHN_BRIDGE_URL` must be HTTPS (or loopback for testing) — the CLI refuses a downgraded page.

Residual risks (not eliminated):

- **Ceremony phishing.** A crafted `bridge.html#...` link plus a local listener with the matching token/port could harvest an assertion over an attacker-chosen challenge. The CLI is the only intended launcher; the page shows the mode and a truncated challenge; and the verifier binds the challenge to `SHA-256(artifact body)`, so a harvested assertion is useless unless the attacker already controls the exact artifact being sealed. Touch ID user-verification is always required.
- **Registration TOFU.** With `attestation: "none"`, the credential public key is trusted on first use over the token-protected loopback channel; there is no Secure Enclave attestation chain. A future hardening could request `attestation: "direct"` and validate Apple Anonymous Attestation.

## Dev Mode

For local development with keys on disk, set `PQC_PRIVATE_KEY_PATH`, `C2PA_PRIVATE_KEY_PATH`, and optionally `ED25519_PRIVATE_KEY_PATH` in `.env`. This is **not recommended for production**. Never commit `OPERATOR_PSEUDONYM_SALT` inline in `.env` for production; use `OPERATOR_PSEUDONYM_SALT_PATH` on the vault instead.
