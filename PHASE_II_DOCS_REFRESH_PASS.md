# Phase II Docs Refresh Pass — T-M5-DOCS

**Date:** 2026-05-13
**Branch:** `stream/shared-public`
**Parent commit:** `480b8bb` (CETM v0.4 additive extension memo — M4.4)
**Integration tip anchored:** `47b9a04` (InvariantCheck v1 — 15/15 invariants)
**Author:** Phase II docs-refresh agent

## Scope

This memo accompanies the workspace-level documentation refresh for
Phase II readiness pack and the workspace-root `SECURITY.md`. The
refresh anchors the readiness pack to the merged engine landings on
`stream/integration` (M1 + 6 engines partial + proposal v0.4 reframe)
and adds the disclosure-pipeline references required by plan §6 C12
and §9 Part A.

**Engineering code untouched.** This is documentation/governance only.
No edits to `aegisgraph/`, `tests/`, `schema/`, or `.github/workflows/`.

## Files updated at workspace level (NOT in any git repo)

These files are workspace-level per `/home/twawe/577i-Projects/SBIR
Working Folder/ASEMA/WORKSPACE_INDEX.md` and are NOT in any git repo.
They are edited in place; no commits accompany them. Confirmation that
they are not under VCS: workspace-level paths are outside the
`AegisGraph_Tier3_Research/` git tree.

### 1. `03_PROPOSAL/phase-ii-readiness/02_project_plan.md`

**Action:** Rewrote milestone task tables to anchor merged engines and
reflect Phase II rollout per plan §5.

**Key changes:**

- **Stream owners table** extended with HarnessGen, InvariantCheck,
  CrossSMA, and Disclosure-pipeline (Engine 6) entries. ReproChain
  reframed as a feeder into HarnessGen native track.
- **M1-M4 task table** anchored to merged commits:
  - T-M1.1 (ADR-0006 disclosure ownership) — done — `79adace`
  - T-M1.2 (schema v2 + ADR-0013) — done — `79adace`
  - T-M1.4 (counsel review) — **BLOCKED — counsel not yet engaged**
  - T-M1.5 (counsel retention) — **BLOCKED**
  - T-M1.6 (schema v2 deltas + ADR-0014) — done — `79adace`
  - T-M1.7 (disclosure ledger init + Engine 6 scaffold) — done —
    `47530ba` (feat) → `93d4565` (merge)
  - T-M2.1 (PolyDiff image family) — done — `ff69dc2`
  - T-M2.2 (PolyDiff opengraph) — done — `20364eb`
  - T-M2.3 (PolyDiff URL refactor) — done — `0f67505`
  - T-M3.1 (HarnessGen native + libwebp) — done — `4d03d7d`
  - T-M3.3 (InvariantCheck v0) — done — `529a341`
  - T-M4.1 (self-hosted runner) — **BLOCKED — Ops resource scheduling**
  - T-M4.3 (proposal v0.4 reframe) — done — `97cbbd3`
  - T-M4.4 (CETM v0.4) — done — `480b8bb`
- **M5-M7 task table** anchored:
  - T-M5.1 (HarnessGen JVM — Signal `LinkPreviewUtil`) — `in flight`
    (sibling worktree today)
  - T-M5.2 (HarnessGen Rust) — PENDING
  - T-M5.3 (InvariantCheck v1 — 15 invariants) — done — `47b9a04`
  - T-M5.4 (PolyDiff deeplink) — `in flight` (sibling worktree today)
  - T-M5.5 (CrossSMA scaffold + matrix) — done — `37e5387`
  - T-M5.6 (first triage gate) — PENDING
  - T-M6.1 (first vendor contact) — **BLOCKED on T-M1.4 counsel**
  - T-M6.2 (first ledger entry) — **BLOCKED on T-M6.1**
  - T-M6.3 (embargo timer cron) — done — `47530ba`
  - T-M7.1 (≥1 disclosure submitted metric) — **BLOCKED on T-M6.1**
  - T-M7.2 (CrossSMA expanded — 6 v0.3 threads covered) — done —
    `37e5387` (matrix populated)
- **M8-M14 task table** added new entries: T-M8.1 (workbench with
  disclosure lane), T-M9.1 (first CVE), T-M10.1 (v0.5 release), T-M13.1
  (M14 demo dry-run), T-M14.1, T-M14.2 (v1.0 release).
- **M15-M24 option** entries added: T-M15.1, T-M16.1, T-M18.1, T-M19.1,
  T-M22.1 (≥5 disclosures cumulative), T-M24.1.
- **Risk table** extended with R-DISC-1 through R-DISC-6 family.
- **Cross-stream dependency block** rewritten to reflect counsel-gated
  disclosure path and HarnessGen track ordering.

**Lines added:** ~120 net (file roughly tripled in row count due to
status column + Engine 6 additions).

### 2. `03_PROPOSAL/phase-ii-readiness/07_disclosure_policy.md`

**Action:** Extended (original v0.3 sections preserved) with v0.4
disclosure-pipeline mechanics.

**Key additions:**

- New section "**Counsel one-time review requirement (BLOCKING for
  first vendor contact)**" — gates Engine 6 dry-run vs send mode.
- Day-7 and Day-14 timeline entries extended: Day-7 adds early MITRE
  CVE submission for MITRE-direct vendors (R-DISC-2 mitigation); Day-14
  adds two-step CERT/CC fallback policy.
- New section "**Per-finding `embargo_days` configurability**" — per
  vendor + per finding override mechanics.
- New section "**Disclosure ledger (ADR-0014)**" — full ledger format
  reference; points to `aegisgraph/disclosure/ledger.jsonl` and
  `schema/disclosure-event.schema.json`; lists required fields, event
  types, actors.
- New section "**Two new claim states**" — `reviewed_embargoed` and
  `disclosed_public` with allowed transitions enforced by
  `aegisgraph/disclosure/claim_states/*.py`.
- New section "**Vendor routing tiers**" — three-tier CNA model
  (vendor_cna / third_party_cna / none) per `vendor_registry.yaml`.
- New section "**First-disclosure target (recommended): Option A —
  libwebp upstream via Chrome CNA**" — rationale + R-DISC-5 PR-risk
  mitigation; Options B/C reserved.
- New section "**Day-14 CERT/CC fallback policy**" — operational
  mechanics tied to `embargo-tick.yml`.
- Logging section: legacy `aegisgraph/docs/disclosure-log/` retained
  for human-readable summary memos; ledger declared **authoritative**.
- "What is NOT disclosed externally" extended to include ledger
  entries with non-`disclosed_public` claim state, vendor security
  contacts, and free-form notes.
- Phase II Month 1 deliverables marked: scaffold landed; vendor
  registry initialized; embargo cron deployed; counsel review and PI
  ratification still gated.

**Lines added:** ~140 net.

### 3. `03_PROPOSAL/phase-ii-readiness/07a_disclosure_legal_review_checklist.md` (NEW)

**Action:** Created per plan §6 B9.

**Contents:**

1. Disclosure policy ratification (`T-M1.4`)
2. First vendor-contact letter template review
3. Indemnification / E&O insurance confirmation
4. DARPA contractual disclosure-notification requirements (Award
   Section H/I verification)
5. IP rights on findings (SBIR Phase II default)
6. CFAA / DMCA §1201 anti-anti-hacking statute review

Each item has WHO / WHEN / WHY BLOCKING / STATUS / acceptance criteria.
Aggregate gate: until ALL six are Resolved, Engine 6 pipeline operates
in dry-run mode only. Re-review triggers + counsel deliverables
retention section included.

**Status:** All six items Unresolved (pre-counsel-retention state).

**Lines:** ~150 new file.

### 4. `SECURITY.md` (workspace root)

**Action:** Extended (no replacement; all existing content preserved).

**Key additions under "Disclosure protocol":**

- Two-step vendor → CERT/CC Day-14 fallback routing language added.
- Per-finding `embargo_days` configurability documented.
- New subsection "**Claim-state lifecycle including disclosure states
  (Phase II v0.4)**" — adds `reviewed_embargoed` and `disclosed_public`
  downstream of `reviewed`; references claim-state guard modules.
- New subsection "**Disclosure ledger format**" — points to
  `aegisgraph/disclosure/ledger.jsonl`,
  `schema/disclosure-event.schema.json`, and ADR-0014.
- New subsection "**CVE workflow**" — three-tier CNA routing table
  referencing `aegisgraph/disclosure/templates/cve_request.j2` and
  `vendor_registry.yaml`.

**Key additions under "Policy review":**

- "Authoritative references for the Phase II disclosure pipeline" list:
  ADR-0014, ADR-0013, ADR-0006, `07_disclosure_policy.md`, the new
  `07a_disclosure_legal_review_checklist.md`,
  `schema/disclosure-event.schema.json`, `aegisgraph/disclosure/`.

**Lines added:** ~50 net.

## Engine code untouched

Confirmation:

- No edits to `aegisgraph/` (any subdir, including `disclosure/`)
- No edits to `tests/` (any subdir)
- No edits to `schema/`
- No edits to `.github/workflows/`
- No edits to `docs/decision-log/` ADR files

The Engine 6 ledger I/O, vendor router, embargo timer, claim-state
guards, and templates that this documentation refresh references all
already exist at integration tip `47b9a04` (merged via `47530ba` +
`93d4565`).

## No overlap with concurrent agents

This refresh works exclusively in:

- Workspace-level documentation (NOT in any git tree)
- This worktree's `PHASE_II_DOCS_REFRESH_PASS.md` (`stream/shared-public`)

Sibling agents working in `.worktrees/harnessgen-jvm/` (T-M5.1) and
`.worktrees/polydiff-deeplink/` (T-M5.4) touch only engineering code
(`aegisgraph/harnessgen/jvm/` and `aegisgraph/polydiff/families/deeplink/`
respectively), neither of which this refresh modifies.

## Verification commands

```bash
# 1. Confirm workspace-level files are NOT in any git tree
cd "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/01_TIER3_RESEARCH/AegisGraph_Tier3_Research/.worktrees/shared-public/"
git status   # should show ONLY PHASE_II_DOCS_REFRESH_PASS.md as new file

# 2. Confirm integration tip is unchanged by this refresh
git log --oneline origin/stream/integration | head -1   # should still be 47b9a04

# 3. Confirm the four workspace files exist and reflect updates
ls -la "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/phase-ii-readiness/02_project_plan.md"
ls -la "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/phase-ii-readiness/07_disclosure_policy.md"
ls -la "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/phase-ii-readiness/07a_disclosure_legal_review_checklist.md"
ls -la "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/SECURITY.md"
```

## Follow-on tasks unblocked by this refresh

- PI can now circulate `07_disclosure_policy.md` v0.4 + counsel
  checklist to outside counsel for retention conversations (T-M1.5)
  and one-time review (T-M1.4).
- M5-DOCS engine landings now have human-readable reviewer-facing
  documentation aligning with the merged schema v2 / ADR-0014 / Engine
  6 scaffold.
- Phase II readiness pack is consistent with integration tip 47b9a04
  for review by DARPA PM at first quarterly check-in.

## Follow-on tasks still blocked

- T-M1.4 / T-M1.5 (counsel) — gates T-M6.1 / T-M6.2 / T-M7.1
- T-M4.1 (self-hosted runner) — gates T-M3.2 / T-M5.2 24h fuzz
- T-M3.6 (sanitize-check Rule 7 wiring) — gates v0.5 release
