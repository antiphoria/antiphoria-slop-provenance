# Gap 7 — SQLite migration plan for `operatorSeals[]`

**Status:** not executed in Phase 0. This is the handoff plan for the Phase 2
implementer who lands witnessing (`operatorSeals[]`, pre-release.md §3 Gap 2).

## Why deferred

The current SQLite `artifact_records` table has a single `cryptographic_signature`
column holding the primary ML-DSA signature only. The hybrid Ed25519 signature
lives only in the markdown artifact and the git branch — not in SQLite. Under
v3 + witnessing, the right shape is to persist the *full* `operatorSeals[]`
array (N entries, each with primary + hybrid signatures + ceremony metadata).

Doing this migration *before* the `operatorSeals[]` schema is finalized would
mean writing the column twice. So the schema migration is bundled with Gap 2.

## What to do in Phase 2 (when landing witnessing)

**Design decision (resolved):** Replace the singular `cryptographic_signature`
column with a single `operator_seals_json` TEXT column holding the full
`operatorSeals[]` array (each entry: primary + hybrid signatures + ceremony
metadata). Do NOT create separate columns for primary/hybrid — the array is
parsed at runtime.

1. **Schema migration** — add `operator_seals_json` column to `artifact_records`
   (TEXT, nullable). Use SQLite's `ALTER TABLE ... ADD COLUMN` (online).

2. **Write path** — `create_artifact_record` and the witness command serialize
   the full `operatorSeals[]` array to JSON and store it in
   `operator_seals_json`. The markdown artifact remains the source of truth.

3. **Read path** — update any consumer of `cryptographic_signature` to
   deserialize from `operator_seals_json` instead.

4. **Grandfathering** — legacy v2 rows (the dev-run artifacts) stay NULL;
   readers fall back to the markdown. The legacy in-memory parse adapter (in
   `parsing.py`) maps `signature`/`hybridSignature` to a single
   `role="sealer"` `operatorSeals[]` entry, so the engine never sees the old
   shape.

5. **Drop** (deferred cleanup) — once all readers use `operator_seals_json`,
   drop `cryptographic_signature` in a separate migration.

## Files this touches (Phase 2)

- `src/repository/types.py` — `ArtifactRecord` gains `operator_seals_json`.
- `src/repository/stores/artifact_store.py` — write/read the new column.
- `src/repository/sqlite.py` — `ALTER TABLE` migration (idempotent).
- `src/commands/pipeline.py` — `_record_signed` passes the seals array.
- `src/commands/witness.py` (new) — witness command appends and re-persists.
