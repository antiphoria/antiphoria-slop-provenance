# user-stories.md — who does what, with what, providing what
 
Companion to `pre-release.md`. Where the pre-release checklist says *what to fix*, this document says *what the system is* — the roles, flows, and data shapes that result. Read this first; it is the source of truth for scope. If `pre-release.md` and this document disagree, this document wins.
 
Status legend: `[settled]` decided · `[open]` needs your call · `[deferred]` acknowledged but not for v3
 
---
 
## 1. Foundational principles (non-negotiable)
 
These are the rules every decision below obeys. They come from you across this conversation.
 
1. **The trust boundary is reputational.** "Human" means "Antiphoria warrants it" — never "the cryptography proves a human pressed a button." No metadata theater: a layer either delivers a real cryptographic guarantee or it's honestly labeled as captured-unverified.
2. **Antiphoria does not hold the license. The author does.** Antiphoria warrants provenance; it does not own the work. The rights block must reflect this. `[settled, requires fix — see §8]`
3. **Hackerist.** No corporate dependencies if a clean self-hosted option exists. We host our own trust world and build whatever is needed to function independently for eternity.
4. **Simplicity.** Derive the clean solution. Prefer deleting over refactoring.
5. **Maximum cryptographic redundancy, cleanly separated.** Each layer hedges a *distinct* failure mode. If a layer hedges what another already hedges, it's ornamental. Layers fail soft.
6. **Install or move on — for Operators.** Producing trust is deliberate and requires the full stack. Consuming trust is zero-install (browser verification).
7. **Writers send text. They do not install anything.** The submission surface for writers is a transport problem (email, paste, git PR), not an install problem.
 
---
 
## 2. Roles (the complete model)
 
Two roles. That's it.
 
### Role A — Writer (the author)
 
- **Who:** Anyone who writes text and wants it registered with Antiphoria. The evening fiction person. The essayist. The journalist. Does not need to be technical.
- **Does:** Writes text in whatever tool they already use (Word, Google Docs, Notes, Scrivener, plain email). Sends the plaintext to an Operator.
- **Needs:** Nothing. No install, no CLI, no keys, no browser ceremony.
- **Provides:** The text + whatever metadata the Operator asks for (pen name, classification, license preference).
- **Gets back:** A registered artifact (the `{requestId}.md` file) and a published URL. The artifact is *theirs* — their license, their pen name, their work. Antiphoria's role is recorded as "witnessed by," never "owned by."
- **Trust property:** "Antiphoria warranted this is human-authored by [writer]." Reputational, backed by however many Operator seals the artifact accumulates.
 
### Role B — Operator (the sealer / witness)
 
- **Who:** The trusted few — you, plus 3–4 friends who install the full stack and commit to the ethos. The Operator population is small by design.
- **Does:** Two distinct acts, both requiring their own vault and keys:
  - **Seal** — receive writer's text, run the ceremony, produce the artifact, anchor it.
  - **Witness** — independently verify and re-sign an artifact another Operator sealed.
- **Needs:** The full v3 stack. liboqs (ML-DSA-44), c2pa-python, the Go `ots` binary, pygit2, the vault. Native deps mandatory. `[settled: ML-DSA mandatory, OD-1]`
- **Provides:** Their signature(s) over the canonical bytes. One signature per seal or witness event.
- **Gets back:** A transparency-log entry under their pseudonym. Their warranty is now part of the artifact's public record forever.
- **Trust property:** "My key sealed this body and I stand behind it." Each Operator's seal is an independent warranty. An artifact with N Operator seals has N independent warranties — strength is visible in the envelope.
 
**Note on the Operator-as-Author case:** An Operator *can* register their own text. They run `register` on their own work — they are simultaneously the Writer (text is theirs) and the Operator (they seal it). The envelope records this honestly: there is one Operator seal, and the rights/license point at the author (them, by pen name). No special path needed.
 
---
 
## 3. Trust properties — what each layer actually proves
 
The complete map. Each row hedges a distinct failure mode. This is the redundancy principle made concrete.
 
| # | Layer | Envelope location | Hedges (the failure mode it covers) | Does NOT hedge |
|---|-------|-------------------|-------------------------------------|----------------|
| 1 | **Writer → Operator transport** | (out of band) | Nothing cryptographic. The Operator warrants the text came from the claimed writer. | Authenticity of the writer's identity. |
| 2 | **Self-declaration Q&A** | `claim.statements` | "The operator didn't ask the right questions before sealing." | The truth of the answers. |
| 3 | **WebAuthn operator presence** | `operator.webauthn` | "The sealing process was hijacked by malware on the Operator's machine" (operator presence check). | Author identity. Proof of personhood. `[requires Flaw A fix]` |
| 4 | **ML-DSA-44 primary signature** | `operatorSeals[].primary` | "A classical algorithm (Ed25519) gets broken — e.g., a future cryptanalytic advance or a quantum adversary." | A break in lattice cryptography. |
| 5 | **Ed25519 hybrid signature** | `operatorSeals[].hybrid` | "ML-DSA-44 gets broken — e.g., a flaw in the lattice scheme or liboqs implementation." | A break in classical curve crypto. |
| 6 | **N Operator seals (witnessing)** | `operatorSeals[]` | "The sealing Operator was compromised, coerced, or acting maliciously." | Collusion of *all* witnessing operators. |
| 7 | **RFC3161 timestamp** | `integrity.timestamps[]` | "The TSA backdates or fabricates a time attestation." Requires the TSA to be compromised. | TSA compromise itself. |
| 8 | **OpenTimestamps (Bitcoin)** | `integrity.sidecars.ots` | "The RFC3161 TSA is compromised or colluding with the Operator." Bitcoin is a separate trust root. | Bitcoin chain reorg (deep, economically infeasible). |
| 9 | **Transparency log (hash chain)** | `.provenance/transparency-log.jsonl` | "The archive is silently mutated after sealing." | Pre-commitment tampering (covered by 7/8). |
| 10 | **Operator pseudonym hash** | `operator.pseudonymHash` | "Continuity is lost — readers can't tell which artifacts came from the same Operator." | Real-world identity of the Operator. |
 
**Key insight — Layer 6 (witnessing) is the only hedge against operator compromise.** Before this layer, every artifact's trust root was a single keypair. Witnessing is what makes the trust multi-party. It's the feature that turns Antiphoria from "one person's signature host" into "a small notary pool." `[settled: add witnessing — see §6]`
 
---
 
## 4. User stories — N=1 (the simple case)
 
The baseline. One writer, one operator, no witnesses yet.
 
### Story 1.1 — Writer submits text
 
> Maya writes a 3,000-word short story in Google Docs. She exports to plain text and emails it to operators@antiphoria.org with the subject "Submission: The Rain in Lisbon" and a note: "Pen name: Maya R., classification: fiction, ARR."
 
- **Actor:** Writer (Maya)
- **What they do:** Send plaintext + metadata via existing transport (email).
- **What they install:** Nothing.
- **What they get back:** A registered artifact URL.
- **Open question `[OD-US-1]`:** What's the actual submission surface? Email today is fine; later it could be a form on antiphoria.org or a git PR to a staging repo. Decided when a real writer arrives.
 
### Story 1.2 — Operator seals
 
> Operator A receives Maya's email. They save the text to `submissions/maya-r-rain-in-lisbon.txt`, create the artifact directory, and run `slop-cli register --file submissions/maya-r-rain-in-lisbon.txt --title "The Rain in Lisbon" --author "Maya R." --license ARR --classification fiction`. The CLI runs the self-declaration Q&A (Operator A warrants this came from Maya), captures WebAuthn presence (Operator A's Touch ID), signs with ML-DSA-44 + Ed25519, anchors to RFC3161 + Bitcoin, and commits to the archive.
 
- **Actor:** Operator (A)
- **What they do:** Convert submission → register command. Run the ceremony. Provide their vault-backed signature.
- **What they need:** Full v3 stack + vault mounted.
- **What they provide:** One `operatorSeals[]` entry (ML-DSA + Ed25519 + WebAuthn presence).
- **What they get back:** A transparency log entry under their pseudonym; the commit OID.
 
### Story 1.3 — Reader verifies
 
> A reader finds Maya's story on mediocre.antiphoria.org. They click "Verify provenance" and are taken to verify.antiphoria.org/?q=<requestId>. The browser fetches the artifact, resolves all keys from the published registry, runs ML-DSA + Ed25519 + C2PA + RFC3161 + OTS verification, and renders a Provenance Card.
 
- **Actor:** Reader (anyone)
- **What they do:** Click a link.
- **What they install:** Nothing. Browser-only.
- **What they get:** A verdict — PASS/WARN/FAIL with per-layer breakdown.
 
### Story 1.4 — Writer requests a correction
 
> Three months later, Maya emails: "I need to fix a copyright flag — I accidentally submitted as ARR but it should be CC-BY-4.0, and there's a paragraph I want to revise." Operator A runs `slop-cli register --file revised.txt --supersedes <old-requestId> --reason copyright-flag --note "Maya requested CC-BY-4.0 and a paragraph revision."`. The new artifact carries a `revision` block linking to the old one; the old one's catalog row gets `supersededBy` filled in.
 
- **Actor:** Writer (Maya) requests; Operator (A) executes.
- **What happens:** A *new* artifact is sealed, not an in-place edit. The old artifact stays honest ("this was the original; it has been superseded by X"). Both are independently verifiable.
- **Trust property:** The version chain is visible. Readers see v1 → v2 and the reason.
 
---
 
## 5. User stories — N+1 writers (the scaling case)
 
Adding more writers changes nothing in the mechanism, only volume.
 
### Story 5.1 — Second writer submits
 
> Tom, a different writer, submits his own story. Operator A registers it. Tom's artifact is completely independent of Maya's — different `requestId`, different `rights` block (Tom's pen name, Tom's license choice), different body. The only shared element is the sealing Operator's pseudonym in `operatorSeals[]`.
 
- **What changes vs. N=1:** Nothing structural. The catalog grows by one row. The Operator has signed one more artifact.
- **Cross-writer linkage:** Only via the shared sealing Operator (visible in the registry) and the shared Bitcoin anchor batch (if they happen to seal near the same block).
 
### Story 5.2 — Multi-author work (deferred)
 
> Maya and Tom co-write a novella. They want both names on the artifact.
 
- `[deferred]` — The `collaborators[]` per-author attestation chain is **out of scope for v3.** Under the current model, the Operator warrants "this came from Maya and Tom" — recorded in `claim` or a free-text field, not cryptographically per-author. If true multi-author cryptographic attestation is needed later, it's a v4 feature and depends on a writer-facing signing surface that doesn't exist yet (and per Story 1.1, writers don't install anything). The envelope can carry an `authors: ["Maya R.", "Tom K."]` display list in v3 without making it a crypto property.
 
---
 
## 6. User stories — N+1 operators (the witnessing case)
 
This is where the trust model becomes multi-party. **The most important scaling axis.**
 
### Story 6.1 — Second operator witnesses
 
> Operator A seals Maya's story. Operator B (a friend, separate machine, separate vault, separate pseudonym) pulls the archive, reviews the artifact, and runs `slop-cli witness --request-id <id> --repo-path <archive>`. The CLI:
> 1. Loads the sealed artifact.
> 2. Runs **full-chain verification** — refuses to witness if any signature, hash, timestamp, or anchor is broken. (A witness is a vote of confidence; witnessing broken work destroys the witness's credibility.)
> 3. Loads Operator B's own keys.
> 4. Computes a fresh ML-DSA-44 + Ed25519 seal over the *same canonical target* Operator A signed.
> 5. Appends Operator B's seal to `operatorSeals[]`.
> 6. Commits the augmented envelope to the artifact branch (append-only — Operator A's seal is never touched).
> 7. Logs a transparency entry under Operator B's pseudonym.
 
- **Actor:** Operator (B), witnessing Operator A's seal.
- **What they need:** Full v3 stack + their own vault + read access to the shared archive.
- **What they provide:** A second `operatorSeals[]` entry.
- **What changes:** The artifact now has 2 independent warranties. The Provenance Card shows "Sealed by Operator A, witnessed by Operator B." Strength is visible.
- **Trust property gained:** Hedging operator compromise. If Operator A's vault is later compromised, Operator B's signature still attests "an independent party checked this at time T and stood behind it."
 
### Story 6.2 — Operator refuses to witness (the legitimacy fork)
 
> Operator B reviews Operator A's seal and suspects misattribution — maybe the text looks machine-generated but is claimed as human. Operator B **does not run `witness`**. No `operatorSeals[]` entry from B is added. The absence is itself information: anyone tracking the operator pool can see "A sealed, B did not witness." The artifact remains valid with A's single seal; it's just weaker, and the absence of expected witnesses is a signal.
 
- **What happens:** Nothing is written. The fork is *visible by absence* — readers who know the operator pool can see "only one operator sealed this" and draw their own conclusions.
- **Open question `[OD-US-2]`:** Should refusals be *recorded* (a negative transparency entry: "Operator B reviewed and declined")? Pro: explicit, auditable. Con: raises the stakes of witnessing, may chill participation. My lean: no — keep refusal as absence. Cheaper, less socially loaded. Revisit if the pool grows past ~10.
 
### Story 6.3 — Operators coordinate via the git archive
 
> Operators A, B, C, and D all have push access to the same `antiphoria-archive` git repo. When A seals, they push to `artifact/<id>`. B, C, D pull, review at their own pace, and run `witness` if they choose. Each witness is a new commit on the same branch (append-only). The branch tip reflects the latest state of the multi-operator warranty.
 
- **Coordination mechanism:** Git push/pull. No new protocol. The "blockchain" is the commit history + the `operatorSeals[]` list. `[settled: git is the coordination layer]`
- **Conflict handling:** If two operators witness concurrently and both push, standard git merge resolves it (the `operatorSeals[]` entries are independent and order-independent — each signs the canonical target, not the previous witness). Merge conflicts on the envelope YAML are possible but mechanical to resolve (re-render + re-commit). `[OD-US-3]`: decide whether to enforce serialized witnessing via a lock or accept concurrent-witness merges.
 
### Story 6.4 — Operator signs their own text (the collapse case)
 
> Operator A writes an essay themselves and wants to register it. They run `slop-cli register --file my-essay.txt --author "Operator A (pen name: A.)" --license CC-BY-4.0`. The envelope has one `operatorSeals[]` entry (A's own seal), and the rights block points at A's pen name. Operator B can witness it like any other artifact.
 
- **What's special:** Nothing, mechanically. The Operator is also the author. The envelope is honest about this — one seal, rights to the author (who happens to be the Operator). No deception, no special path.
 
---
 
## 7. Data shapes — what the artifacts and front-ends look like
 
The concrete shapes that fall out of the stories above.
 
### 7.1 v3 envelope (the sealed artifact)

The wire format is `eternity.v3` — evolved from v2 by threading the role split, witnessing, versioning, and the license-owner correction all the way through. v2 artifacts remain *parseable* (grandfathered dev-run input only); new seals emit v3 exclusively.

```yaml
---
antiphoria:
  schemaVersion: "eternity.v3"
  profile: "<antiphoria.register.v1 | antiphoria.seal.v1>"   # human | synthetic
  pipelineVersion: "<semver>"
  ledgerRequestId: "<uuid>"                                  # git branch artifact/<uuid>

document:
  artifactId: "<uuid>"
  title: "<string>"
  createdAt: "<ISO-8601 UTC>"
  contentType: "text/markdown"

author:                                                        # NEW — the work's owner
  penName: "<string>"                                          #   as the writer declared it
  classification: "fact | opinion | fiction | satire"          #   (interactive mode only)
  # NO key material here. The author is not a cryptographic actor in v3.
  # The Operator warrants "this came from <author>." The author holds the license.

revision:                                                      # NEW (Gap 1) — absent on first version
  chainRoot: "<requestId of v1>"
  sequence: 2                                                  # 1-based
  supersedes: "<requestId of v1>"
  supersedesHash: "<payloadHash of v1>"                        # content commitment, NOT a dependency
  reason: "copyright-flag | error-correction | plagiarism-removal | editorial | other"
  note: "<free text>"

rights:                                                        # FIX (Flaw F) — owner is the AUTHOR, not antiphoria
  policyId: "ARR | CC-BY-4.0 | CC0-1.0 | <custom>"
  holder: "<author penName or legal name>"                     # NEW field
  notice: "© 2026 <holder>. All Rights Reserved."              # was: "© 2026 antiphoria. All Rights Reserved."
  statement: "<full legal license text, attributed to holder>"

operatorSeals:                                                 # NEW (Gap 2 replaced) — 1..N independent warranties
  - operatorPseudonymHash: "<64 hex>"
    role: "sealer"                                             # "sealer" (register/seal) | "witness" (witness command)
    sealedAt: "<ISO-8601>"
    ceremony:
      orchestratorCommit: "<git sha of slop-provenance at ceremony>"
      webauthn:                                                # operator presence check (Flaw A — verified for real)
        credentialId: "<base64url>"
        clientDataJson: "<base64url>"                          # NEW — full clientDataJSON, not just hash (Flaw A)
        clientDataJsonHash: "<64 hex>"
        authenticatorData: "<base64>"
        signature: "<base64>"
        fmt: "<string>"
    primary:                                                   # ML-DSA-44 — mandatory, always present (OD-1)
      algorithm: "CRYSTALS-Dilithium (NIST ML-DSA-44)"
      signerFingerprint: "<hex>"                               # FIX (Flaw E) — derived from PUBLIC key
      signature: "<base64>"
    hybrid:                                                    # Ed25519 — always present
      algorithm: "Ed25519"
      signerFingerprint: "<hex>"
      signature: "<base64>"

claim:                                                         # speech-act metadata (unchanged shape)
  speechAct: "self-declaration | orchestration-declaration"
  provenanceGrade: "declared | unattended"
  source: "human | synthetic"                                  # "hybrid" removed (curate deleted)
  mode: "interactive | unattended"
  statements: [ { id, question, answer } ]

# seal profile only:
synthesis:
  modelId: "<string>"
  modelsUsed: [ ... ]
  processNarrative: { sidecar, contentHash, verified: false, disclaimer }   # optional

integrity:                                                     # payload + anchors (witnessing augments, doesn't replace)
  payloadHash: "<64 hex sha256 of canonical body>"
  canonicalization: "eternity.canonicalization.v1"
  timestamps:
    - kind: rfc3161
      provider: "<TSA URL>"
      token: "<base64 RFC3161 TSR>"
  sidecars:
    c2pa: "<requestId>.c2pa"
    ots: ".provenance/ots-<requestId>.ots"
    processNarrative: "<requestId>.process.json"               # seal only, optional
---
<canonical markdown body>
```

**What's gone vs. v2:** the singular `operator.webauthn` block (now inside each `operatorSeals[]` entry); the `operator.pseudonymHash` top-level field (now per-seal); `claim.classification` (moved to `author`); the `hybrid` source class; MVP C2PA mode; the v1 wire codec; Supabase remote-log fields; `prevHash` (OD-2 — removed).

**Key invariant:** each `operatorSeals[]` entry signs the *same canonical target* — the envelope with all `operatorSeals[].primary.signature` / `.hybrid.signature` fields excluded, plus the payload hash. So N operators each independently sign identical bytes; their seals don't depend on each other and verify independently.

### 7.2 The registry (verification keys) — published, multi-operator

The published key registry (`registry.json` in `web-ui`) grows to one entry per Operator. The browser verifier resolves every `operatorSeals[].primary.signerFingerprint` and `.hybrid.signerFingerprint` against it, plus the WebAuthn COSE public keys (Flaw A).

```json
{
  "schemaVersion": "antiphoria.key-registry.v3",
  "operators": [
    {
      "slug": "operator-a",
      "operatorPseudonymHash": "<64 hex>",
      "keys": {
        "mlDsa44":  { "fingerprint": "<pubkey-derived>", "publicKeyB64": "...", "publicKeySha256": "..." },
        "ed25519":  { "fingerprint": "<pubkey-derived>", "publicKeyB64": "...", "publicKeySha256": "..." },
        "webauthn": [ { "credentialId": "...", "publicKeyCoseB64": "...", "rpId": "antiphoria.org" } ]
      }
    },
    { "slug": "operator-b", "operatorPseudonymHash": "...", "keys": { ... } }
  ]
}
```

**Fingerprint rule (Flaw E):** `fingerprint == publicKeySha256[:32]` for every tier. A third-party verifier can recompute every fingerprint from published public material alone.

### 7.3 Catalog row (the index)

```jsonl
{ "requestId": "...", "title": "...", "author": { "penName": "Maya R." }, "source": "human",
  "rightsHolder": "Maya R.", "license": "ARR",
  "chainRoot": "...", "sequence": 1, "supersedes": null, "supersededBy": null,
  "operatorSealCount": 2, "operators": ["operator-a", "operator-b"],
  "branch": "artifact/...", "commitOid": "...", "artifactHash": "...",
  "hasC2pa": true, "hasProcessNarrative": false, "indexedAt": "..." }
```

The catalog is the place where version chains and witness counts become *queryable* without walking every envelope.

### 7.4 Front-end implications

- **`mediocre.antiphoria.org` / `organic.antiphoria.org`** (the journals): byline shows `author.penName` (not "Antiphoria"). License notice attributes to `rights.holder`. Provenance card shows the seal count: "Sealed by Operator A, witnessed by Operator B." A superseded artifact renders a banner: "Superseded by v2 — read the current version."
- **`verify.antiphoria.org`**: resolves every `operatorSeals[]` entry against the registry; verifies each independently; shows a per-operator row in the verdict. WebAuthn becomes a real check (Flaw A), not "field present."
- **`operators.antiphoria.org`**: each Operator gets a profile keyed by `operatorPseudonymHash` showing every artifact they've sealed or witnessed. The byline split (sealer vs. witness) is visible per artifact.
- **No writer-facing front-end in v3.** Submission is transport (email today). `[OD-US-1]`

---

## 8. The license fix (Flaw F) — non-negotiable

`src/policies/license_text.py` currently hardcodes `_PUBLISHER = "antiphoria"` and emits e.g. `© 2026 antiphoria. All Rights Reserved.` as the `rights.statement` for *every* sealed human artifact. This is a legal misattribution: Antiphoria is claiming copyright on work that belongs to the author. Under principle 2 ("Antiphoria does not hold the license"), this is wrong and must be fixed before any further sealing.

**Fix shape:**
- [ ] `rights.holder` becomes a required field, populated from the author declaration (pen name or legal name).
- [ ] `LicenseText` templates substitute `{holder}` for the hardcoded publisher.
- [ ] The dev-run artifact `af19b5fa-...` (sealed with `© 2026 antiphoria`) is a known-bad legacy; v3 sealing never emits this shape again.

Recorded as **Flaw F** in `pre-release.md`.

---

## 9. The N+1 × N+1 matrix

You asked: what do texts, seals, and frontends look like with N+1 writers and N+1 operators? Here is the full picture.

### 9.1 Seal count = independent warranty count

An artifact with K operator seals has K independent warranties. The matrix:

| | 1 operator | 2 operators | 3 operators | 4 operators |
|---|---|---|---|---|
| **1 writer** | 1 seal. Weakest. Single trust root. | 2 seals. Hedged against one operator compromise. | 3 seals. Strong. | 4 seals. Notary-pool strength. |
| **2 writers** | Each artifact: 1 seal. Independent artifacts. | Each artifact can accumulate up to 2 seals independently. | ... | ... |
| **N writers** | Volume scales, per-artifact strength unchanged. | Witnessing scales per-artifact, independent of writer count. | ... | ... |

**Key scaling properties:**
- **Writer count and operator count scale independently.** Adding writers doesn't change per-artifact strength; adding operators does.
- **Witnessing is per-artifact and opt-in.** Not every artifact needs every operator's seal. Routine work might get 2 seals; significant work might aim for all 4.
- **The catalog's `operatorSealCount` field** lets readers filter: "show me only artifacts with ≥3 operator seals" if they want the strongest warranties.

### 9.2 What changes in each layer as N grows

- **Texts (the body):** nothing. One body hash, signed by everyone. Writer count is just artifact count.
- **Seals (`operatorSeals[]`):** grows from 1 to N entries. Each is independent. Order doesn't matter (each signs the canonical target, not the previous seal).
- **Front-ends:** the byline stays the author's. The provenance card grows a row per witnessing operator. The operators site grows a profile per operator. No new UI concepts.
- **Archive:** more branches (`artifact/<id>`), more commits (one per witness event), more transparency-log entries. All append-only. Git handles it.
- **Coordination (git):** push/pull. Operators witness at their own pace. Concurrent witnesses merge mechanically (independent entries).

### 9.3 Failure modes as N grows

- **1 operator compromised, N=4:** the other 3 seals still attest. Artifact remains strongly warranted. The compromised operator's *other* artifacts are suspect, but that's a separate per-operator investigation visible in the registry.
- **2 operators collude, N=4:** the other 2 seals still attest. Strength degrades but doesn't collapse. Visible in the seal count.
- **All operators collude:** the system is broken — but so is every trust system when every trusted party is malicious. The mitigation is *social* (choose operators who don't trust each other much), not cryptographic.
- **An operator disappears:** their existing seals still verify (registry is published). No new seals from them. The witness pool shrinks. Their work remains honest.

---

## 10. Open decisions (user-stories scope)

`[OD-US-1]` **Submission surface.** Email today. Form/git-PR later. **Decision deferred until a real writer arrives.** Not a v3 blocker.

`[OD-US-2]` **Record refusals-to-witness?** Lean: no — refusal is visible by absence. Revisit if the pool grows past ~10. **Defer.**

`[OD-US-3]` **Concurrent witnessing: lock or merge?** Lean: accept concurrent-witness merges (entries are independent). Add a serialization lock only if merge conflicts prove painful in practice. **Defer — start with merge.**

`[OD-US-4]` **Witnessing for synthetic (seal profile) artifacts too, or human (register) only?** Lean: allow witnessing for both — it's the same primitive (operator attests to an artifact's integrity), and synthetic work also benefits from multi-operator warranty. **Tentative yes for both; confirm before implementing.**

---

## 11. Sequencing (how this lines up with pre-release.md)

This document defines the target state. `pre-release.md` defines the work to get there. They share phases:

- **Phase 0 — Cleanup & corrections (unblocked now):** safe-deletes (generate, curate, SDK, MVP C2PA, Supabase, v1 wire), Flaw D (v3 schema bump), Flaw E (fingerprint), Flaw C (redact relabel), Flaw F (license owner), Gap 7 (hybrid sig in SQLite).
- **Phase 1 — WebAuthn verification (Flaw A):** makes operator presence real. Code lands now; production re-enroll waits on `antiphoria.org` (Flaw B).
- **Phase 2 — Product shape:** Gap 1 (versioning, §7.1 `revision`), Gap 2-replacement (witnessing, §6 + §7.1 `operatorSeals[]`), Gap 4 (split install not needed — writers send text).
- **Phase 3 — Domain resolution:** Flaw B completes; the two dev-run artifacts are grandfathered as legacy/unverified-presence.

Each phase is independently shippable. Phase 0 alone produces a smaller, more honest, legally correct codebase.

---

## 12. Out of scope for v3 (explicitly)

- Writer-facing signing surface (browser WebAuthn for writers). Writers send text.
- `collaborators[]` per-author cryptographic attestation. Multi-author works carry an `authors[]` display list only.
- Pure-decentralized DAG without an Operator. That's a different product (a notary network, not a publisher).
- New cryptographic algorithms beyond ML-DSA-44 + Ed25519. Maximalism is expressed through witnessing, not more sig schemes.
- Hosted anything. Self-hosted, sovereign, forever.

If a real requirement emerges in any of these, it's a v4 conversation.