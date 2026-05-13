# Proposal v0.4 Reframe Pass — Coordination Memo

**Task:** T-M4.3 — Proposal narrative reframe: abstract + §5.2 + §5.8 engines section + adjacent additive edits

**Branch:** `stream/shared-public`

**Date:** 2026-05-12

## Summary

The master proposal v0.3 has been amended into v0.4 as an *additive* incremental version that reframes the AegisGraph narrative from "evidence-centered assessment system" to "graph-driven automated vulnerability discovery system." Every v0.3 claim is preserved without retraction; section numbering is held stable so existing citations remain valid; new content is concentrated in:

- The abstract (new opening sentence + discovery-by-M14 commitment),
- §1 Executive Summary evaluator-story (expanded to discovery loop),
- §2 What We Are Not Claiming (one additional boundary row),
- §5.2 Architecture (table rewritten from 7 components → graph-as-planner + 6 engines),
- §5.3 Schema (appended paragraph introducing schema v2 / ADR-0013),
- §5.5 Claim-state lifecycle (two new states: Reviewed-Embargoed, Disclosed-Public),
- §5.6 Score vector (appended paragraph introducing engine_corroboration + exploitability_evidence as optional v2 dimensions),
- §5.8 NEW — Discovery Engines (Detail): ~2,650-word subsection covering PolyDiff Extended, HarnessGen, InvariantCheck, CrossSMA, DynamicProbe (option-period), Coordinated Disclosure, plus an engine-coordination summary,
- Changelog appendix (~1,350 words) enumerating every v0.3 → v0.4 additive delta and explicitly committing to non-retraction of v0.3 claims.

## Master proposal paths

- v0.3 (frozen, citable baseline): `/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.3.md`
- v0.4 (this amendment): `/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md`

## Diff statistics

- v0.3: 1,096 lines
- v0.4: 1,225 lines
- Net delta: +129 lines (smaller than the plan's rough "1,000-1,500 lines" estimate because the additions are dense prose paragraphs rather than verbose bullet expansion; substantive word-count delta is ~4,000 new words concentrated in §5.8 and the changelog).
- Diff hunks (sections touched): top-of-file version banner; abstract; §1 evaluator story; §2 boundaries table; §5.2 architecture; §5.3 schema; §5.5 claim-state table; §5.6 score-vector trailer; §5.8 (new); changelog appendix (new).

## Verification — quick spot-check commands

```bash
# Compare line counts
wc -l "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.3.md" \
      "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md"

# Spot-check diff hunks
diff -u "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.3.md" \
        "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md" | grep '^@@'

# Verify no v0.3 evidence record hashes changed (the substantive non-retraction commitment lives in engineering, not the markdown — but the proposal claim is auditable against the v0.3 cetm.json and traceability matrix)
ls -la "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package/04_evidence/v0.3/"
```

## Out of scope (per plan §9 versioning + task scope)

The following are explicitly deferred to later milestones and were *not* touched in this v0.4 pass:

- §6.6 ReproChain and §6.7 PolyDiff reframe to "Engine 1/Engine 2 evidence" framing — deferred (later milestone). The abstract and §5.2 already point to the engine reframe; the §6 evidence subsections retain v0.3 wording so existing citations into those subsections remain stable.
- §9 milestone table rewrite to discovery-deliverable framing — deferred to T-M7.3.
- §6.X new evidence subsections per engine (HarnessGen libwebp run, InvariantCheck library, CrossSMA matrix, Disclosure ledger) — each engine writes its own evidence subsection at later milestones as engineering output lands.
- CETM v0.4 (`04_evidence/v0.4/cetm.json` with 6 new claim families `C-NEW-{HG,IC,CS,DP,CD}` + `C-SCHEMA-V2` at status P) — handled by T-M4.4 in a separate agent run.
- F15–F22 figure pack (engine architecture, discovery loop, engine schematics, schema v2 diagram, disclosure pipeline) — deferred. v0.4 text references the F15+ pack as "forthcoming" and continues to render F1–F14 as v0.3.
- §14 risk table extension with R-DISC-1 through R-DISC-6 — deferred. The Phase II plan §15 already documents these risks; folding them into the master §14 is deferred to avoid surfaces for v0.3-to-v0.4 inconsistency claims.
- §17 references extension (Asemarefactor.md, Project Zero policy, CERT/CC VINCE, MITRE CVE form) — deferred to keep v0.3→v0.4 reference numbering stable.
- §13 team table — PhD-level vulnerability researcher hire remains out of scope (per the plan R-PROP-2 flag).

## Coordination notes for adjacent workstreams

- **T-M4.4 (CETM v0.4):** the v0.4 markdown references the v0.4 CETM in the abstract footnote and the changelog appendix; T-M4.4 should produce `04_evidence/v0.4/cetm.json` that extends v0.3's 69 claims with the 6 new claim families (all status P at cut). The v0.4 markdown does *not* assume any specific row count for v0.4 CETM, only that the 6 new families exist.
- **ADR-0013 / ADR-0014 authoring (engineering integration stream):** v0.4 text cites ADR-0013 (schema v2) and ADR-0014 (hash-chained disclosure ledger) repeatedly. These ADRs need to land on `stream/integration` for the citations to resolve. Schema v2 integration commit range cited in §5.3 is `0f67505…529a341` — engineering should preserve this range or update the citation when the actual commits land.
- **Engineering modules (per engine workstreams):** v0.4 §5.8 references `aegisgraph/{polydiff,harnessgen,invariants,crosssma,dynamicprobe,disclosure}/` module paths. These directories must exist (even as scaffolding) by M4 for the proposal references to be evidence-anchored.
- **Worktree topology:** v0.4 master proposal is at workspace level, NOT inside this worktree's git tree. The proposal file is not version-controlled by `stream/shared-public`; only this coordination memo is. The diff vs v0.3 is auditable via the two filesystem paths in §"Master proposal paths" above.

## Commit plan

This memo is committed to `stream/shared-public` as the auditable record of the v0.4 proposal pass; the v0.4 markdown itself sits at workspace level and is not git-tracked here. Commit message follows the HEREDOC template in the task definition.
