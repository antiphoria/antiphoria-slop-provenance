# Security: Key Handling (BYOV)

## Security Audit Remediation (Breaking Changes)

The following changes were made to address cryptographic and integrity vulnerabilities. **Existing artifacts and transparency logs may be incompatible.**

- **Merkle tree:** RFC 6962-style domain separation (leaf vs internal node hashing) and odd-node promotion (no duplication). Merkle roots will change. `verify_merkle_proof` now accepts optional `tree_size` for odd-sized trees.
- **Null bytes:** Artifacts containing `\x00` are rejected (no longer stripped). Invalid payloads raise `RuntimeError`.
- **JSON canonicalization:** `canonical_json_bytes` now uses RFC 8785 (JCS). Existing signatures may break if the previous output differed from JCS.
- **Path traversal:** `tree_get_blob` and `tree_get_entry` reject `..`, `.`, and absolute paths with `ValueError`.

## Threat Model

Private keys (ML-DSA `private.key`, C2PA `c2pa-private-key.pem`, and Ed25519 `ed25519_private.pem`) must never be written to disk at runtime. The BYOV (Bring Your Own Vault) architecture ensures **zero-disk-exposure**: keys are provided via secure, volatile mounts. The application receives paths to keys in RAM or on a temporarily mounted volume; when the process exits, the launcher unmounts or deletes the volatile storage.

## Bootstrap Flow

1. **Generate ML-DSA keys:** `python scripts/gen-mldsa-keys.py`
2. **Generate C2PA keys:** `./scripts/gen-c2pa-keys.ps1` (Windows) or `./scripts/gen-c2pa-keys.sh` (Linux)
3. **Generate Ed25519 keys:** `python scripts/gen-ed25519-keys.py`
4. **Move `c2pa-root-ca.key.pem` to offline USB** (never store on disk with other keys)
5. **Create vault manually** (see below)
6. **SECURE CLEANUP:** Delete `keys/private.key`, `keys/c2pa-private-key.pem`, and `keys/ed25519_private.pem` from disk after populating the vault.
7. **Keep `public.key`, `c2pa-cert-chain.pem`, and `ed25519_public.pem` on disk**; reference via `.env` (`OQS_PUBLIC_KEY_PATH`, `C2PA_SIGN_CERT_CHAIN_PATH`, `ED25519_PUBLIC_KEY_PATH`)

## Manual Vault Creation

### Windows (VeraCrypt)

Scripting VeraCrypt container creation via CLI is brittle across Windows builds. Use a 100% manual flow:

1. Open VeraCrypt
2. Click **Create Volume** → choose **Standard** volume
3. Select path: `keys_vault.hc` (project root)
4. Choose size (e.g. 10 MB)
5. Set a strong password
6. Format as **FAT32**
7. Mount the new volume, copy `private.key`, `c2pa-private-key.pem`, and `ed25519_private.pem` from `keys/` into it
8. Unmount
9. **SECURE CLEANUP:** Delete `keys/private.key`, `keys/c2pa-private-key.pem`, and `keys/ed25519_private.pem` from your SSD.

### Linux (GPG)

From project root:

```bash
tar cf keys_vault.tar -C keys private.key c2pa-private-key.pem ed25519_private.pem
gpg -c keys_vault.tar
rm keys/private.key keys/c2pa-private-key.pem keys/ed25519_private.pem
```

This produces `keys_vault.tar.gpg`. The `rm` step removes the plaintext originals from disk. The archive is flat so `run-secure.sh` finds files at `$RAMDIR/private.key`, `$RAMDIR/c2pa-private-key.pem`, and `$RAMDIR/ed25519_private.pem`.

## Runtime Flow

Use the launcher to mount/extract the vault, inject key paths, run the app, and clean up:

- **Windows:** `./run-secure.ps1 slop-cli generate --prompt "..." --repo-path <path>`
- **Linux:** `./run-secure.sh slop-cli generate --prompt "..." --repo-path <path>`

If no arguments are passed, the launcher starts an interactive shell with the environment variables set.

## Windows UAC

Virtual volume mounting requires **Administrator privileges**. Run PowerShell as Administrator before invoking `run-secure.ps1` (or the script will exit with an error). If the session is elevated, the mounted drive may be in the Administrator context; `EnableLinkedConnections` can affect visibility across user contexts.

## Multi-Process (Windows)

If the vault is already mounted (e.g. notary in one terminal), a second `run-secure.ps1` detects it, reuses the drive, injects env, runs the child, and does **not** unmount. The first session unmounts when done.

## Dev Mode

For local development with keys on disk, set `PQC_PRIVATE_KEY_PATH`, `C2PA_PRIVATE_KEY_PATH`, and optionally `ED25519_PRIVATE_KEY_PATH` in `.env`. This is **not recommended for production**.
