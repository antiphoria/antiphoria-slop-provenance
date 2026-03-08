# Security Incident Rotation Checklist

Use this checklist when any credential appears in repository history.

## Required actions

- Revoke the exposed credential at the upstream provider immediately.
- Generate a replacement credential with least-privilege scope.
- Update local `.env` only (never commit real credentials).
- If the credential is used in CI, rotate the corresponding GitHub secret.
- Record rotation time and owner in internal incident notes.

## Verification

- Confirm the leaked literal no longer appears in git history.
- Confirm the leaked literal no longer appears in current working tree.
- Confirm pre-commit and CI secret scanners are blocking new leaks.
