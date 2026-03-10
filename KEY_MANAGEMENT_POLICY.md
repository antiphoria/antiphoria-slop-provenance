# Key Management Policy

Operational policy for ML-DSA signing keys used by the provenance engine.

## 1. Key custody

- Store private keys in a dedicated secure location with strict filesystem permissions.
- Never commit private keys into git history.
- Use separate key material for development and production environments.

## 2. Fingerprint and versioning

- Every signing key must have a stable fingerprint.
- Track key lifecycle with explicit versions (for example: `v1`, `v2`).
- Register active key metadata in the local key registry.

## 3. Rotation

- Rotate signing keys on a schedule or immediately after suspected compromise.
- After rotation, maintain public verification material for historical signatures.
- Update environment values (`PQC_PRIVATE_KEY_PATH`, `OQS_PUBLIC_KEY_PATH`, and version metadata) atomically.

## 4. Revocation

- Mark compromised keys as revoked in the key registry immediately.
- Preserve revocation logs and incident notes for auditability.
- Do not delete old verification data needed to validate historical artifacts.

## 5. Backup and recovery

- Maintain encrypted, offline backups of active private keys.
- Periodically test restore procedures in a non-production environment.
- Record backup and restore events in an operational log.

## 6. C2PA certificate operations

- For validator-grade C2PA, use a dedicated X.509 signing certificate chain and private key.
- Keep C2PA cert-chain/key material separate from ML-DSA keys and rotate independently.
- Validate EKU/KU and trust-chain requirements before enabling `C2PA_MODE=sdk`.
- Treat `ENABLE_C2PA=true` with `C2PA_MODE=sdk` as fail-closed operational mode.
- Store C2PA signer material in secure secret storage (KMS/HSM or equivalent) for production.
