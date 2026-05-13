# CETM v0.4 Extension Pass (T-M4.4)

**Task:** Extend the v0.3 Claim → Evidence Traceability Matrix (CETM) additively
to back the claims in master proposal v0.4 (the discovery-system reframe,
six named engines, schema v2, two new claim states, two new optional score-vector
dimensions). Authored: 2026-05-12.

**Branch:** `stream/shared-public` (this memo committed here for cross-stream
visibility; CETM files themselves live at workspace level — see paths below).

## What this pass produced (workspace-level, not in any git)

The CETM data files live at workspace paths (consistent with v0.3 placement):

- `03_PROPOSAL/active-package/04_evidence/v0.4/cetm.json` — the v0.4 CETM.
- `03_PROPOSAL/active-package/04_evidence/v0.4/README.md` — additive-delta doc.
- `03_PROPOSAL/active-package/04_evidence/v0.4/checksums.sha256` — SHA-256 over
  the two files, verified with `sha256sum -c`.

Validator change (also workspace-level):

- `03_PROPOSAL/active-package/05_verification/validate-cetm.mjs` — extended with
  a `--version v0.3|v0.4` flag, an explicit claim-ID pattern check, the v0.4
  `<planned>` sentinel for `evidence_artifact` on status=P rows, and a
  v04-new-families summary block in the validator output. **All v0.3 rules are
  preserved.**

## Counts (validator output)

| Version | Total claims | A | E | P | issues_count | exit |
|---|---:|---:|---:|---:|---:|---:|
| v0.3 | 69 | 48 | 8 | 13 | 0 | 0 |
| v0.4 | 82 | 52 | 9 | 21 | 0 | 0 |

v0.4 net delta from v0.3: **+13 claims** across the families listed below.

## New claim IDs added at v0.4

| Claim ID | Status | Engineering anchor (when A/E) |
|---|---|---|
| `C-SCHEMA-V2` | A | `tests/test_schema_v1_v2_compatibility.py` (89-case regression) + ADR-0013 + schema commit range `0f67505…529a341` |
| `C-NEW-HG` (HarnessGen) | A | `aegisgraph/harnessgen/` tree + `reprochain/harness/libwebp/WebPDecodeRGB.harness.cc` + `tests/harnessgen/` @ integration:`4d03d7d` |
| `C-NEW-IC` (InvariantCheck) | A | `aegisgraph/invariants/manifest.json` (5 invariants) + library + `tests/invariants/` @ integration:`4d03d7d` |
| `C-NEW-CS` (CrossSMA) | P | scaffold deferred to M5.5 |
| `C-NEW-DP` (DynamicProbe) | P | option period only; signed authorization required |
| `C-NEW-CD` (Coordinated Disclosure) | A | `aegisgraph/disclosure/` tree (ledger + vendor registry + pipeline + templates + claim-state guards + embargo cron) + `tests/test_disclosure_ledger.py` + `tests/disclosure/` + ADR-0006/0014 (commit `79adace`) |
| `C-NEW-PD-EXT` (PolyDiff Extended) | E | `aegisgraph/polydiff/` subpackage (URL family refactored at `0f67505`; image family in flight; opengraph/qr/proto deferred to v0.5) |
| `C-DISC-V1` … `C-DISC-V5` | P | placeholder reservations for the first five disclosure events; gated on counsel review + PI sign-off + qualifying finding |
| `C-SOTA-DELTA` | P | M14 baseline-tool delta report deliverable |

## Additive-only promise (verified)

Every v0.3 claim (all 69) is present in `04_evidence/v0.4/cetm.json` with the
same `claim_id`, `source_location` (still pointing to v0.3 master line numbers —
those don't change under additive amendment), `claim_text`, and `status`. The
v0.4 build script (`/tmp/build_v04_cetm.mjs`, ephemeral) deep-copied the v0.3
claim array verbatim with `JSON.parse(JSON.stringify(...))`, then appended the
13 new claims. No v0.3 claim was edited, retracted, or renumbered.

## Validator extension (T-M4.4 changes to `validate-cetm.mjs`)

1. **`--version v0.3|v0.4` flag** — selects the default CETM path
   (`04_evidence/<version>/cetm.json`) and is reflected in the summary output.
2. **Claim-ID pattern** — explicit `/^C-[A-Z0-9][A-Z0-9-]*$/` check; permissive
   so new families don't need validator edits.
3. **New family registry** — explicit tracking of `C-SCHEMA-V2`, `C-NEW-HG/IC/CS/DP/CD`,
   `C-NEW-PD-EXT`, `C-DISC-V[0-9]+`, `C-SOTA-DELTA` in the summary block
   (reporting purpose only; validation remains via the generic pattern).
4. **`<planned>` sentinel** — when `evidence_artifact == "<planned>"`, the
   on-disk check is skipped; allowed only for `status == "P"` (status A or E
   rows using the sentinel produce a hard failure).
5. **`evidence_hash` typing** — null or string; status-{P, E} rows are allowed
   null (already the v0.3 behavior, now explicit in the comment + an
   `evidence_hash` type guard).
6. **All v0.3 rules preserved** — A-row in-package-path resolution, E/P-row
   missing-path soft warnings, multi-path splitting on `+`, fragment/query/section
   trimming. v0.3 file still validates with `issues_count: 0` and exit `0`.

## Verification commands (both must pass)

```bash
cd "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package"

# v0.3 — must remain 0 issues
node 05_verification/validate-cetm.mjs --version v0.3 04_evidence/v0.3/cetm.json
# v0.4 — must be 0 issues
node 05_verification/validate-cetm.mjs --version v0.4 04_evidence/v0.4/cetm.json

# Checksum verification (run from v0.4 dir)
cd 04_evidence/v0.4 && sha256sum -c checksums.sha256
```

All three commands pass at the time of this memo.

## Cross-references

- **Master proposal v0.4** (the document this CETM backs):
  `03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md`
  (proposal narrative agent's commit `97cbbd3` on `stream/shared-public`).
- **Phase II plan** (T-M4.4 task definition): `/home/twawe/.claude/plans/so-i-have-a-structured-milner.md` §9 Part A.
- **v0.3 CETM** (preserved baseline): `03_PROPOSAL/active-package/04_evidence/v0.3/cetm.json`.
- **Engineering tip at v0.4 cut:** `4d03d7d85c979d46d6f258039f4136dba53388ba` on
  `origin/stream/integration` (verify with
  `git -C <integration-worktree> log -1 --format='%H' origin/stream/integration`).
- **ADRs referenced** (accepted in stream/integration commit `79adace`):
  ADR-0006 (disclosure ownership; PI as named owner; counsel review the one
  blocking gate), ADR-0010 (additive-only schema evolution policy), ADR-0013
  (schema v2 discovery-graph additive extension), ADR-0014 (hash-chained
  coordinated-disclosure ledger).

## Status-promotion roadmap (planned, per master changelog)

- M4 (now): scaffold-anchored claims at A — `C-SCHEMA-V2`, `C-NEW-HG`,
  `C-NEW-IC`, `C-NEW-CD`. `C-NEW-PD-EXT` at E (URL family refactored + image
  family in flight). `C-NEW-CS`, `C-NEW-DP`, `C-DISC-V1..V5`, `C-SOTA-DELTA`
  at P.
- M7: HG/IC/CD promote forward (vendor-contact, more invariants, more harnesses).
- M10: CS promotes to E (≥1 confirmed cross-target propagation).
- M14: HG/IC/CD/CS targeted to A (≥1 `disclosed_public` ledger entry; ≥2 SMAs
  end-to-end for CS); `C-SOTA-DELTA` produced.
- M19/M24 (option): `C-NEW-DP` promotes (first authorized crash; runtime ↔ static
  correlation report).

## What this pass did NOT do (deferred)

- Did not edit any v0.3 claim. v0.3 file on disk is unchanged.
- Did not produce ADR files (ADRs are referenced by commit `79adace` per
  the engineering convention — they are tracked as governance metadata in
  the engineering commit log, not as separate files in this proposal package).
- Did not run engineering tests. The `verification_command` fields are
  documentation; running them is the engineering streams' responsibility.
- Did not push the commit. Push is the user's call.
