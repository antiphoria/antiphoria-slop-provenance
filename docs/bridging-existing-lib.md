# Bridging antiphoria_sdk to the existing slop CLI keys

The `antiphoria_sdk` package is intentionally **not** coupled to `src.adapters` or
`src.services`. Your factory or a thin integration layer can still reuse the
**same cryptographic material** as
`src/adapters/crypto_notary.py` by adapting bytes into `antiphoria_sdk.signing.HybridKeys` and passing `antiphoria_sdk.signing.HybridSigner` to `antiphoria_sdk.chain.SealEngine`.

## What matches today

- **ML-DSA**: The SDK uses **ML-DSA-44** and the same `import oqs` / algorithm
  string as the notary.
- **Ed25519**: The SDK uses **raw 32-byte** Ed25519 private/public keys
  (`cryptography` raw encoding), compatible with keys exported in that form.

## What differs

- **Artifact format**: Markdown provenance artifacts signed by the CLI use a
  different message domain than SDK `ChainRecord` JSON. They are separate
  chains of trust unless you explicitly define a cross-link in metadata.
- **Fingerprint**: SDK `HybridKeys.fingerprint` is a **synthetic** SHA-256 over
  `mldsa_public || ed25519_public`, truncated to 32 hex characters. The CLI
  may expose a different signer fingerprint string for ML-DSA / Ed25519 PEM
  registration; compare documents carefully before treating them as
  interchangeable identifiers.
- **Fingerprint binding**: `SealEngine` enforces that the fingerprint embedded
  in each `Signature` matches `signer.public_key_fingerprint`. A custom
  adapter MUST return a `Signature` whose `public_key_fingerprint` equals the
  value its `Signer.public_key_fingerprint` attribute advertises, or
  `_build_sign_and_write` raises `ChainError` before the record reaches disk.

## Algorithm agility (D-1 prep)

`Signature.algorithm` is validated against a permissive identifier pattern
(`ml-dsa-44+ed25519`, `ml-dsa-65+ed25519`, `slh-dsa-sha2-128s+ed25519`, ...),
not a closed enum. A chain produced by a future SDK release with an upgraded
post-quantum suite parses cleanly on older readers; *acceptance* is the
verifier's job. The default `HybridVerifier` still rejects anything other
than the suite it was built for and logs a warning. Bring-your-own verifier
implementations may opt into additional algorithm strings without an SDK
schema bump.

`Signature.key_id` is a forward-compat **rotation / epoch slot** carried on
the wire so future consumers can disambiguate re-issued or versioned key
material that shares a fingerprint history. It is informational on the
default verifier; bridges that mint signatures from a KMS / HSM SHOULD set
`key_id` to a stable rotation tag (e.g. `"factory-2026-Q2"`) via
`HybridSigner(keys, key_id=...)`. Records sealed without a `key_id`
serialize as `"key_id": null` and verify identically; tagged records verify
so long as the corresponding `HybridKeys` remain registered with the
verifier (key resolution is still by `public_key_fingerprint`; `key_id`-based
lookup is a future hook).

## Performance characteristics

`HybridVerifier.verify` instantiates a fresh `oqs.Signature` context per
call. This is correct but not free: liboqs setup involves a significant
malloc/init pass. If you bridge this into a hot path (e.g. verifying long
chains repeatedly), reuse one `SealEngine` for multiple `verify_chain`
calls or cache verifiers per fingerprint at the adapter layer.

## Suggested adapter shape (pseudo-code)

Implement `antiphoria_sdk.signing.Signer` with:

- `public_key_fingerprint`: return a `HybridKeys(...).public_only().fingerprint`
  after you assemble `HybridKeys` from your PEM or env-loaded bytes. This
  attribute is read by `SealEngine` for fingerprint binding (see above).
- `sign(data: bytes) -> antiphoria_sdk.Signature`: delegate to `HybridSigner(keys).sign(data)`.

Do **not** import `src.adapters.crypto_notary` from inside `antiphoria_sdk`.
Keep the adapter in your factory repo or an optional `src/runtime/sdk_bridge.py`
in this repo if you choose to add it later.

## Environment loader

`antiphoria_sdk.load_keys_from_env()` expects base64-encoded **raw** key bytes
under:

- `ANTIPHORIA_MLDSA_PRIVATE_KEY_B64` / `ANTIPHORIA_MLDSA_PUBLIC_KEY_B64`
- `ANTIPHORIA_ED25519_PRIVATE_KEY_B64` / `ANTIPHORIA_ED25519_PUBLIC_KEY_B64`

These names are **SDK-specific** and differ from `PQC_PRIVATE_KEY_PATH` and
`ED25519_PRIVATE_KEY_PATH` used by the CLI. A bridge layer should map one
configuration story to the other without merging the modules.

## Cross-process safety

`SealEngine` acquires a `filelock.FileLock` on `<workspace>/chain/.chain.lock`
while writing each record. Two adapters/processes pointed at the same
workspace will not corrupt the chain on disk, but each engine's in-memory
`latest_step` / `latest_hash` may go stale after a peer write. To recover,
construct a new engine via `SealEngine.resume(...)`, which re-validates the
chain and rebuilds in-memory state from disk.
