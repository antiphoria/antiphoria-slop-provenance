# Content License Policy

This policy defines default licensing behavior for generated artifacts based on provenance class.

## Provenance classes

- `human`: Content authored directly by a human contributor.
- `hybrid`: Content materially co-produced via human and model collaboration.
- `synthetic`: Content produced predominantly by model generation.

## Default licenses

- `human` -> All rights reserved (ARR) by default.
- `hybrid` -> CC BY 4.0 by default (attribution required).
- `synthetic` -> CC0 1.0 by default.

## Wire format (`eternity.v2`)

Canonical notice and statement strings for each `rights.policyId` live in
`src/policies/license_text.py` and are rendered into every artifact's
`rights.notice` and `rights.statement` fields. Only `policyId` is bound in the
cryptographic signing target; notice/statement are display and legal prose on
the committed markdown envelope.

- **ARR (register):** notice `© 2026 antiphoria. All Rights Reserved.` plus a
  formal all-rights-reserved statement naming antiphoria as publisher.
- **CC0-1.0 (seal):** notice `🅍 CC0 1.0 • Public Domain • antiphoria` plus
  the CC0 1.0 Public Domain Dedication text.

## Important notes

- These defaults can be changed by the operator for specific projects.
- License assignment does not replace legal review for jurisdiction-specific rights.
- Provenance metadata and cryptographic signatures are evidence artifacts; they are not a substitute for legal adjudication.
