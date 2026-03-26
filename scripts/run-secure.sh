#!/usr/bin/env bash
# BYOV launcher for Antiphoria Slop Provenance (Linux only)
# Decrypts GPG vault to RAM, injects key paths, runs command, cleans up on exit.
# Requires: gpg, keys_vault.tar.gpg at project root.
# NOTE: Uses /dev/shm (Linux tmpfs). macOS and Windows lack this; on Windows use
# scripts/run-secure.ps1. macOS users need an alternative (e.g. $TMPDIR or RAM disk).

set -e -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULT_PATH="${KEYS_VAULT_PATH:-$SCRIPT_DIR/keys_vault.tar.gpg}"

if [[ ! -f "$VAULT_PATH" ]]; then
  echo "Error: Vault not found: $VAULT_PATH. Create keys_vault.tar.gpg per SECURITY.md." >&2
  exit 1
fi

RAMDIR="/dev/shm/slop-keys-$$"
trap 'rm -rf "$RAMDIR"' EXIT

mkdir -p "$RAMDIR"
gpg -d "$VAULT_PATH" | tar -xC "$RAMDIR"

if [[ ! -f "$RAMDIR/private.key" ]]; then
  echo "Error: Missing private.key in vault. Add per SECURITY.md." >&2
  exit 1
fi
if [[ ! -f "$RAMDIR/c2pa-private-key.pem" ]]; then
  echo "Error: Missing c2pa-private-key.pem in vault. Add per SECURITY.md." >&2
  exit 1
fi

chmod 600 "$RAMDIR/private.key" "$RAMDIR/c2pa-private-key.pem"

export PQC_PRIVATE_KEY_PATH="$RAMDIR/private.key"
export C2PA_PRIVATE_KEY_PATH="$RAMDIR/c2pa-private-key.pem"
if [[ -f "$RAMDIR/ed25519_private.pem" ]]; then
  chmod 600 "$RAMDIR/ed25519_private.pem"
  export ED25519_PRIVATE_KEY_PATH="$RAMDIR/ed25519_private.pem"
fi

if [[ $# -gt 0 ]]; then
  "$@"
else
  "$SHELL"
fi
