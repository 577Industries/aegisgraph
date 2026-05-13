# Proposal v1.0 — Narrative Cut Coordination Memo

**Date:** 2026-05-13
**Wave:** 10C (parallel with Waves 10A pin-resolution + 10B public-release cut + 10D m14-demo)
**Branch:** stream/shared-public
**Engineering integration tip referenced:** `origin/stream/integration` HEAD `0a91fc6` (1014 tests passed; 19 skipped)

## Summary

v1.0 master proposal cut after the M14 engineering demo dry-run. The v1.0
narrative is an **additive extension** of v0.4.1: new §7.4 (engine evidence
at v1.0 cut) and §7.5 (disclosure-pipeline readiness), an Appendix A v1.0
anchoring block, and a Changelog v0.4.1 → v1.0 delta sub-section. The v0.4
master proposal at `01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md`
is **preserved untouched** so prior citations remain stable.

## Workspace-level edits this pass

The proposal lives at workspace path `03_PROPOSAL/active-package/`, which is
NOT a git-tracked directory. The artifact deltas below are recorded here so
they are auditable against this commit's date stamp.

### 1. NEW file: v1.0 master proposal

- **Created:** `03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v1.0.md`
- **Origin:** copy of `AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md` (1,434 lines)
- **Final size:** 1,531 lines (+97 lines net additive)
- **v0.4 file preserved untouched:** 1,434 lines (verified)

### 2. Edits applied to v1.0 file (and v1.0 file only)

| Edit | Section | Description |
|---|---|---|
| 1 | Title | "(v0.4.1)" → "(v1.0)" |
| 1 | Date line | Reworded to "2026-05-13 (v1.0 cut after M14 engineering demo dry-run; v0.4.1 finalization pass dated 2026-05-13; v0.4 amendment of v0.3, dated 2026-05-04)" |
| 1 | Version note | Rewritten to "v1.0 cut after M14 engineering demo dry-run. Every v0.4/v0.4.1 claim preserved without retraction. v1.0 adds (a) §7.4 engine evidence at v1.0 cut paragraph; (b) §7.5 disclosure-pipeline readiness paragraph (honest counsel-blocked state). All section numbering preserved — existing §7.2 (v0.3 SOTA Matrix) and §7.3 (What This Comparison Proves) anchors retained unchanged; the v1.0 narrative additions are placed at §7.4 and §7.5 so prior citations remain stable." Prior version notes (v0.4 amendment of v0.3; v0.4.1 finalization additions) preserved verbatim. |
| 2 | §7.4 (NEW) | Engine evidence at v1.0 cut — per-engine state table for 6 engines; reviewer-packet workflow citation; baseline-tool delta scaffold reference; M14 demo dry-run script reference |
| 3 | §7.5 (NEW) | Disclosure-pipeline readiness — full pipeline shipped; 0 real entries; T-M1.4/T-M1.5 counsel-block reference; libwebp upstream first-target recommendation (ADR-0006); 39 tests pass against pipeline + ledger format |
| 4 | Appendix A | v1.0 anchoring block appended after the existing v0.4.1 anchoring block — integration tip `0a91fc6`; wave summary (Waves 7-10); v1.0 tarball SHA cross-reference placeholder ("will be added by Wave 10B coordination memo"); reviewer reproduction recipe at the v1.0 tip |
| 5 | Changelog | NEW sub-section `### v0.4.1 → v1.0 delta (2026-05-13)` after the existing `### v0.4 → v0.4.1 delta` block; documents the §7.4/§7.5 numbering rationale and the additive-only posture |

### 3. Section-numbering decision (per Critical Constraint 2)

The Agent 10C brief originally specified "NEW §7.2" and "NEW §7.3" but the
v0.4.1 file already has §7.2 (v0.3 SOTA Matrix) and §7.3 (What This Comparison
Proves) — both are stable citation anchors. The brief's fallback clause —
"(or as a new subsection within §7 if §7.2 doesn't exist)" — combined with
Critical Constraint 2 ("Section numbering preserved. Existing §-anchors must
still resolve.") makes the cleanest reading: extend §7 with new §7.4 and §7.5
rather than collide with §7.2/§7.3. This decision is documented inline in the
v1.0 file's version note and in the Changelog v0.4.1 → v1.0 delta sub-section.

### 4. PDF render

- **Tool:** `05_verification/render-master-pdf.py`
- **render-master-pdf.py constants edited:** `SOURCE_MD` v0.4 → v1.0; `OUTPUT_HTML`/`OUTPUT_PDF` v0.4.1 → v1.0; title and page-banner strings v0.4.1 → v1.0
- **Constants reverted post-render** to v0.4.1 (so future v0.4.1 re-renders still work)
- **PDF produced:** `06_rendered_outputs/AegisGraph_ASEMA_DP2_Master_Proposal_v1.0.pdf`
- **Size:** 7,568,424 bytes (7.57 MB)
- **SHA-256:** `1ed7a5afe4a4b2ff659afa307e7bb391c724c16365d7a693d51121b9e073716b`
- **v0.4.1 PDF preserved** at `06_rendered_outputs/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.1.pdf` (7.29 MB / SHA `0b597abd06421f730070a793bb360c4782f50cf208b03f465bb58eef4ef9cc37`) for citation stability.

## Pre-render gates (all green)

```
node 05_verification/validate-evidence.mjs                                        → safety_scan: passed; exit 0
node 05_verification/validate-cetm.mjs --version v0.4 04_evidence/v0.4/cetm.json  → issues_count: 0; exit 0
```

The safety scan now sees the v1.0 file in `01_master_proposal/` and confirms:
- No private absolute `/home/...` paths
- No OpenAI-style secrets
- No private key blocks
- No raw target source markers
- No static-only "confirmed vulnerability" claims
- No live-target probing claims

## Cross-references

- **Wave 10A (pin-resolution):** parallel agent (no file overlap)
- **Wave 10B (public-release cut):** parallel agent — will produce the v1.0 sanitized public release tarball SHA which the v1.0 master proposal Appendix A currently references as "will be added by Wave 10B coordination memo"
- **Wave 10D (m14-demo):** parallel agent (no file overlap)

## Reviewer verification commands

```bash
cd "03_PROPOSAL/active-package"

# v1.0 master proposal exists alongside v0.4
ls -la 01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md          # 1,434 lines / preserved
ls -la 01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v1.0.md          # 1,531 lines

# Section anchors preserved
grep -c "^### 7\." 01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v1.0.md  # 5 (7.1, 7.2, 7.3, 7.4, 7.5)
grep -c "0a91fc6" 01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v1.0.md   # ≥2

# Validators green
node 05_verification/validate-evidence.mjs                                      # exit 0
node 05_verification/validate-cetm.mjs --version v0.4 04_evidence/v0.4/cetm.json  # exit 0

# PDF rendered
ls -la 06_rendered_outputs/AegisGraph_ASEMA_DP2_Master_Proposal_v1.0.pdf        # 7.57 MB
sha256sum 06_rendered_outputs/AegisGraph_ASEMA_DP2_Master_Proposal_v1.0.pdf
# 1ed7a5afe4a4b2ff659afa307e7bb391c724c16365d7a693d51121b9e073716b

# v0.4.1 PDF still re-renderable (constants reverted)
grep "v0.4.1.pdf" 05_verification/render-master-pdf.py                          # OUTPUT_PDF still points at v0.4.1
```

## Known follow-ups (NOT in this pass)

- **Wave 10B tarball SHA cross-reference:** the v1.0 Appendix A anchoring block intentionally leaves "v1.0 sanitized public release tarball SHA: will be added by Wave 10B coordination memo" as a forward reference. Once Wave 10B lands, a one-line edit to the v1.0 file fills the cross-reference. This is the only known scheduled edit to the v1.0 file post-cut.
- **Submission binder regeneration to v1.0:** the binder (`submission-binder/ASEMA_DP2_Master_Proposal_AegisGraph.pdf`) is still the v0.4.1-era output. Binder bump to v1.0 is a future small task (would require re-running the binder render with the v1.0 source).
- **CETM v0.4 → v1.0 promotion:** the CETM is still `cetm.json` at the v0.4 level. v1.0 cetm.json is a future milestone task per the plan; status promotion of the C-DISC-V1..V5 claim families from P → E is gated on T-M1.4/T-M1.5 counsel review (external block).

## Definition of done

- [x] v1.0.md created as copy of v0.4.md
- [x] v0.4.md preserved untouched (1,434 lines)
- [x] Edit 1 applied (title + version banner + version note)
- [x] Edit 2 applied (new §7.4 engine evidence at v1.0 cut)
- [x] Edit 3 applied (new §7.5 disclosure-pipeline readiness)
- [x] Edit 4 applied (Appendix A v1.0 anchoring block)
- [x] Edit 5 applied (Changelog v0.4.1 → v1.0 delta sub-section)
- [x] No private absolute paths in v1.0.md (validator green)
- [x] validate-evidence.mjs returns exit 0
- [x] validate-cetm.mjs --version v0.4 returns issues_count: 0
- [x] v1.0 PDF rendered at 7.57 MB
- [x] PDF SHA-256 recorded: `1ed7a5afe4a4b2ff659afa307e7bb391c724c16365d7a693d51121b9e073716b`
- [x] render-master-pdf.py constants reverted to v0.4.1 post-render
- [x] v0.4.1 PDF preserved at `06_rendered_outputs/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.1.pdf` (untouched)
- [x] Section numbering preserved (all §7.1, §7.2, §7.3 anchors still resolve)
- [x] No v0.4 or v0.4.1 claim retracted

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
