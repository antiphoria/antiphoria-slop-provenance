# Phase 1: Secrets & Credential Audit – Remediation Checklist

This document tracks remediation for the Phase 1 security audit. **Do not commit secrets or private keys.**

---

## Audit Findings Summary

| Severity | Finding | Status |
|----------|---------|--------|
| 🔴 CRITICAL | Live Google API key in `.env` | Action required |
| 🔴 CRITICAL | ML-DSA private key in `keys/ml_dsa_private.raw` | Action required |
| 🟡 LOW | PII/path disclosure (`OQS_INSTALL_PATH`) in `.env` | Addressed via `.env.example` |

---

## Immediate Actions (Manual)

### 1. Revoke the Exposed Google API Key

- Go to [Google AI Studio](https://aistudio.google.com/) or [Google Cloud Console](https://console.cloud.google.com/)
- Revoke the key `***REMOVED***` **immediately**
- Generate a new API key for development/production
- Store the new key only in your local `.env` (never committed)

### 2. Rotate the ML-DSA Private Key

- The key in `keys/ml_dsa_private.raw` is **compromised**
- Generate a new ML-DSA key pair using the snippet below (or your key generation procedures)
- Follow **Section 4 (Revocation)** of `KEY_MANAGEMENT_POLICY.md`: mark the old key fingerprint as revoked in your transparency ledger
- Store the new private key in a secure location **outside** the repository
- Update `.env` with the new key path

**Key generation snippet** (use the context manager to avoid memory leaks from liboqs C-bindings):

```python
import oqs
from pathlib import Path

KEYS_DIR = Path("./keys")  # or a secure location outside the repo
KEYS_DIR.mkdir(parents=True, exist_ok=True)

with oqs.Signature("ML-DSA-44") as sig:
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()

# Persist keys outside the context manager
(KEYS_DIR / "ml_dsa_private.raw").write_bytes(secret_key)
(KEYS_DIR / "ml_dsa_public.raw").write_bytes(public_key)
```

### 3. Sanitize Your Local `.env`

- Replace `OQS_INSTALL_PATH` with a generic placeholder (e.g. `/path/to/liboqs`) or remove it if not needed
- Ensure no workstation-specific paths or usernames remain
- Use `.env.example` as the public template; keep `.env` local and gitignored

---

## Git History Verification

**Current status:** `git log --all -- .env keys/ml_dsa_private.raw` returned **no commits**. These files do **not** appear in the repository history.

- `.env` and `keys/` are correctly listed in `.gitignore`
- If you ever packaged or shared the repo with these files included (e.g. via zip, tarball), treat them as exposed and complete the revocation steps above

### If History Scrubbing Is Ever Needed

If future investigation shows `.env` or `keys/ml_dsa_private.raw` were committed:

```bash
# Install git-filter-repo: pip install git-filter-repo
git filter-repo --path .env --invert-paths
git filter-repo --path keys/ml_dsa_private.raw --invert-paths
```

**Warning:** `git filter-repo` rewrites history. Coordinate with collaborators and force-push only after backup.

---

## Files Added in This Remediation

- **`.env.example`** – Safe template with placeholders; no secrets, no PII paths
- **`SECURITY_AUDIT_PHASE1_REMEDIATION.md`** – This checklist

---

## Pre-Publication Checklist

Before making this repository public:

- [ ] Google API key revoked and rotated
- [ ] ML-DSA private key rotated; old fingerprint revoked in ledger
- [ ] `.env` contains no secrets, PII, or workstation paths (or is excluded from any distribution)
- [ ] `keys/` directory contains no private keys in the repo
- [ ] Git history verified clean (or scrubbed if needed)
