# Provenance Retention Policy

Retention and continuity requirements for long-term provenance verification.

## Retention targets

- Keep signed artifact markdown files indefinitely.
- Keep transparency log entries indefinitely.
- Keep RFC3161 timestamp tokens and verification metadata indefinitely.
- Keep key registry lifecycle records (active, rotated, revoked) indefinitely.
- Keep audit reports for all externally published artifacts.

## Storage strategy

- Primary storage: local ledger repository and local provenance database.
- Secondary storage: regular encrypted backups in separate physical/cloud location.
- Optional tertiary storage: public mirror of transparency log entries.

## Continuity controls

- Validate transparency log hash-chain integrity on a schedule.
- Re-verify a sample of historical artifacts periodically.
- Preserve old public keys and trust chain material for historical verification.

## Incident response

If any provenance store is corrupted or unavailable:

1. isolate affected environment;
2. restore from latest verified backup;
3. run full-chain audit on critical artifacts;
4. publish an integrity incident note for collaborators.
