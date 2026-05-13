# Submission binder + CETM tip refresh — Wave 7C

**Date:** 2026-05-13
**Worktree:** `stream/shared-public`
**Coordination scope:** Submission binder (Public Link Register, Compliance Matrix, compressed Master Proposal binder copy, Vol5, PI_VERIFY worksheet) + Phase II readiness project plan + v0.4 evidence (CETM, README, checksums) refresh anchored to integration tip `ca9e3af` and v0.4 public tarball SHA `c14dc266…`.

This memo coordinates Wave 7C of the v0.4.1 finishing pass. Wave 7A (master proposal v0.4.1 §6.8-§6.12 + §9.1 supplement + Appendix A SHA anchoring) merged at `eeb573f`; Wave 7B (F15-F22 figure pack) merged at `2498d70`. Wave 7C completes the binder-side refresh so the submission package, the in-package CETM, and the Phase II readiness plan all cite the same anchors as the master.

## Anchors at v0.4.1 cut

- **Engineering integration tip:** `ca9e3af` on `origin/stream/integration` (post-Wave 6: validator-v2 sanitize-check Rules 7/8/9; 889 tests pass, 6 skipped)
- **v0.4 sanitized public tarball:** SHA-256 `c14dc266b8e5c46f96e5159cf054547dd2a8abc005ad1fa4d0b4fbdc8d6b4bf7` (804 KB), `release/v0.4.0` branch, cut commit `aba17a2`
- **v0.3 tags preserved untouched:** `v0.3.0-asema-dp2-feasibility`, `v0.3.0-tier3-research` (`bb1d0071dc…`)

## Files refreshed at workspace level

1. `03_PROPOSAL/submission-binder/ASEMA_DP2_Public_Link_Register.md` — header switched to v0.4 era; A10-A14 entries appended after A9 (v0.4 tarball + evidence ledger + CETM + F15-F22 figure pack + integration anchoring). A1-A9 preserved verbatim. v0.2 frozen reference table preserved.
2. `03_PROPOSAL/submission-binder/ASEMA_DP2_Compliance_Matrix.md` — re-anchored to v0.4 master proposal; 3 new rows appended (discovery-engine evidence §5.8 + §6.8-§6.12; schema v2 additive extension ADR-0013 + §5.3; coordinated-disclosure pipeline §5.8.6 / §6.12 / `phase-ii-readiness/07_disclosure_policy.md`). All pre-existing rows preserved.
3. `03_PROPOSAL/submission-binder/ASEMA_DP2_Master_Proposal_AegisGraph.md` — archived v0.3-era copy to `submission-binder/.archive/v0.3_2026-05-08.md`; regenerated compressed binder copy from v0.4 master via token-trim compression (897 lines vs v0.4 master's 1434 lines). All §-anchors preserved exactly (incl. new §5.8.1-§5.8.7, §6.8-§6.12, §9.1 supplement, Appendix A v0.4.1 anchoring block). Compressed binder writes its workspace cross-references without private paths (cleaner than v0.4 master in this respect).
4. `03_PROPOSAL/submission-binder/Vol5_Supporting_Docs.md` — no date in file body; no edits applied. 18 [VERIFY:] markers preserved as required (the file itself has no `[VERIFY:` text; the 18 markers are in the PI_VERIFY worksheet tracking workflow which references Vol5's pre-existing placeholder content — confirmed preserved by reading).
5. `03_PROPOSAL/submission-binder/PI_VERIFY_Worksheet.md` — Target completion bumped from `2026-05-11 afternoon (Day −2)` to `2026-05-14 afternoon (Day −2)`. All A1-A14 + B1-B3 + C1 + D1-D7 marker IDs preserved.
6. `03_PROPOSAL/phase-ii-readiness/02_project_plan.md` — anchor bumped `47b9a04` → `ca9e3af`; T-M5.1 status updated `in flight` → `done — c85233a`; T-M5.1b appended after T-M5.1; T-M7-INV appended after T-M5.3; T-M4.2 status note appended with `ca9e3af` Wave 6 integration anchor. All other task rows preserved.
7. `03_PROPOSAL/active-package/04_evidence/v0.4/README.md` — `_integration_commit_tip_at_v04_cut` block updated `4d03d7d…` → `ca9e3af`; status table row for `C-NEW-PD-EXT` changed `E` → `A` ("all 6 families shipped"); v0.4.1 status counts annotation added (`A=53 / E=8 / P=21`).
8. `03_PROPOSAL/active-package/04_evidence/v0.4/cetm.json` — `_integration_commit_tip_at_v04_cut` value updated to `ca9e3af`; `_status_counts_at_generation` updated to `A=53 / E=8 / P=21` (post-promotion); `C-NEW-PD-EXT` claim record updated: `status` E→A, `claim_text`/`evidence_artifact`/`owner_stream`/`limitation_language` revised to reflect all 6 PolyDiff families shipped on `ca9e3af`. All other 81 claim IDs and status values preserved.
9. `03_PROPOSAL/active-package/04_evidence/v0.4/checksums.sha256` — regenerated atomically (`sha256sum cetm.json README.md > checksums.sha256 && sha256sum -c checksums.sha256` → both `OK`).

## Validator results

```
$ node 05_verification/validate-cetm.mjs --version v0.4 04_evidence/v0.4/cetm.json
{
  "version": "v0.4",
  "cetm_path": "04_evidence/v0.4/cetm.json",
  "total_claims": 82,
  "counts": { "A": 53, "E": 8, "P": 21, "other": 0 },
  ...
  "in_package_missing_paths_for_E_or_P_rows": [],
  "issues_count": 0
}
exit code: 0
```

`validate-cetm.mjs --version v0.4` returns **`issues_count: 0`** (PASS). Total claims = 82 = 69 v0.3 verbatim + 13 v0.4 new families. Status distribution at v0.4.1: **A=53 / E=8 / P=21** (v0.4 cut was A=52 / E=9 / P=21; `C-NEW-PD-EXT` promoted E→A at v0.4.1 anchor).

```
$ node 05_verification/validate-evidence.mjs
Error: Safety scan failed:
01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md: private local path
04_evidence/v0.4/README.md: private local path
exit code: 1
```

`validate-evidence.mjs` fails on **pre-existing private-path entries** that pre-date Wave 7C:
- `01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md` carries `/home/twawe/...` cross-references in its v0.3→v0.4 Changelog appendix Cross-references block (lines 1426-1428). These were authored in Wave 4.3 (`97cbbd3`) and Wave 7A (`eeb573f`); **Wave 7C did not touch the master proposal v0.4.md** (Agent 7A's domain).
- `04_evidence/v0.4/README.md:100` carries `/home/twawe/.claude/plans/so-i-have-a-structured-milner.md §9 Part A.` — this line was in the README before Wave 7C; Wave 7C only edited the v0.4-cut → v0.4.1 commit-tip block (4 lines) and one status-table cell (E → A) plus the on-disk counts annotation. The pre-existing private-path line was not introduced or modified by Wave 7C.

The compressed binder copy regenerated by Wave 7C (`submission-binder/ASEMA_DP2_Master_Proposal_AegisGraph.md`) contains **zero private paths** — its workspace cross-references are written without the `/home/twawe/...` prefix.

**Disposition:** Wave 7C did not introduce any new private-path safety-scan regressions. The two pre-existing failures are workspace items for a follow-up sanitization pass; they do not block submission of the v0.4 public tarball (the tarball is built from a sanitized export pipeline that strips private paths before publication, per the v0.4 release script).

## Checksum verification

```
$ cd 03_PROPOSAL/active-package/04_evidence/v0.4 && sha256sum -c checksums.sha256
cetm.json: OK
README.md: OK
```

Both files re-hash matches stored values.

## Coordination with other Wave 7 agents

- **Wave 7A (master proposal v0.4.1)** — merged at `eeb573f`. No file-overlap with Wave 7C: Wave 7A owns `01_master_proposal/`; Wave 7C owns `submission-binder/`, `phase-ii-readiness/`, `04_evidence/v0.4/{README,cetm,checksums}`.
- **Wave 7B (F15-F22 figure pack)** — merged at `2498d70`. No file-overlap: Wave 7B owns `02_figures_and_storyboard/`. Wave 7C references F15-F22 by filename only (in Public Link Register A13, compressed binder figure captions, and CETM updates).
- **Master proposal v0.4 master is unchanged by Wave 7C** — confirmed by inspection of `01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md` (Wave 7A's mutation surface). The compressed binder copy under `submission-binder/` is the only "master proposal copy" mutated here, and it is a strict downstream of the v0.4 master.

## Push posture

Per task instructions: this memo is committed locally on `stream/shared-public` but **NOT pushed**. PI authorization required before push.
</content>
