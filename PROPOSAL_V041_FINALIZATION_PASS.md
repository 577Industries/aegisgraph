# Proposal v0.4 → v0.4.1 finalization pass — Wave 7A coordination memo

**Date:** 2026-05-13
**Branch:** `stream/shared-public`
**Wave:** 7A (proposal narrative)
**Plan reference:** `/home/twawe/.claude/plans/so-i-have-a-structured-milner.md` §21
**Engineering anchor:** `origin/stream/integration` HEAD `ca9e3af` (889 passed; 6 skipped)
**v0.4 release tarball SHA:** `c14dc266b8e5c46f96e5159cf054547dd2a8abc005ad1fa4d0b4fbdc8d6b4bf7` at `577-Industries/asema-feasibility-artifacts release/v0.4.0` (commit `aba17a2`)

## Scope

This memo records Wave 7A — the proposal-narrative finalization pass that lifts the master proposal from v0.4 to v0.4.1. The master proposal lives at workspace path

```
/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md
```

It is not tracked in any git repository (workspace-level document). All v0.4 claims are preserved without retraction; v0.4.1 is additive.

## Edits applied

1. **Version banner (top of file):** `v0.4 → v0.4.1`; date stamp `2026-05-12 → 2026-05-13`; version note extended with the v0.4.1 finalization-pass enumeration (engine evidence subsections, §9.1 supplement, F15-F22 figure pack pointer, Appendix A SHA citations, Changelog appendix update; non-retraction reaffirmed).

2. **§5.3 Evidence Graph Schema:** appended Figure 22 forthcoming reference for the schema v2 additive overlay (F15-F22 pack).

3. **§6.8 Engine 1 — PolyDiff Extended:** new subsection inserted after existing §6.7. Documents the six-family discipline (url / image / opengraph / deeplink / qr / proto), per-family anchored corpora (libwebp CVE-2023-4863 + 16 historical/synthetic cases), triage classifier, hash-chain provenance, and 89-case schema v1/v2 regression. Limitation note retained ("parser disagreement is not a vulnerability claim").

4. **§6.9 Engine 2 — HarnessGen:** new subsection. Documents the 5 concrete harnesses meeting the M7 ≥2N + ≥2J + ≥1R distribution requirement (libwebp `4d03d7d`, libavif `49bcdc9`, Signal LinkPreviewUtil `68b8abd`, Element X media `c85233a`, matrix-rust-sdk MessageType `b4bdf4d`), Jinja2 template rendering, ASAN+UBSan flags, hash-only crash schema. Limitation: live 24h fuzz deferred to self-hosted runner (T-M4.1 ops-blocked).

5. **§6.10 Engine 3 — InvariantCheck:** new subsection. Documents the 15-invariant manifest with 12 production at v0.4.1 cut (10 CodeQL + 2 Semgrep), full table with MASTG/SSDF mappings (INV-01 through INV-15), SARIF consolidator emission shape, anchored-claim-state default. Limitation: ground-truth pass deferred to T-M7-GT.

6. **§6.11 Engine 4 — CrossSMA:** new subsection. Documents the 4-target registry (Signal `1043851` + Element X `91d265e6` verified, Wire/Telegram stubs deferred to M22.1), deterministic SHA-256 pattern fingerprint, 24-cell candidate matrix (6 graph_threads × 4 targets), and 5-target-per-finding fan-out cap (R-ENG-4). Limitation: 1 validated cell at v0.4.1 (`AG-XSMA-VALIDATED-SIG-GP-001-ELX`); remaining 23 cells stay `candidate_path` honestly.

7. **§6.12 Engine 6 — Coordinated Disclosure:** new subsection. Documents the full ADR-0014 pipeline (hash-chained JSONL ledger, vendor registry covering 7 vendors, pipeline modules, Jinja2 templates, claim-state extensions `reviewed_embargoed` / `disclosed_public`, embargo timer cron). Names libwebp upstream via Chrome CNA as Option A first-disclosure target. **Limitation (explicitly stated):** ledger contains **0 real entries** at v0.4.1 cut; first-contact dispatch BLOCKED on T-M1.4 / T-M1.5 (counsel review + counsel retention); claim IDs C-DISC-V1..V5 remain at status P.

8. **§9.1 Discovery-deliverable supplement table:** new sub-table added AFTER (not replacing) the existing Period | Focus | Major output table. Six rows (M4, M7, M10, M14, M19, M24) with columns for discovery deliverable, engineering gate, CETM promotion, and external blocks. M4 row anchors to `ca9e3af` and `c14dc266…`; M7 and downstream rows surface T-M1.4/T-M1.5 (counsel) and T-M4.1 (runner) as the binding external blocks.

9. **Appendix A — Reproducibility & code references:** appended a v0.4.1 anchoring block citing the v0.4 tarball SHA, the `ca9e3af` integration tip, and a four-command reviewer reproduction recipe (`git checkout ca9e3af && devcontainer up && make tooling-strict && python3 -m pytest -q`).

10. **Changelog appendix — v0.4 → v0.4.1 delta sub-section:** new sub-section inserted BEFORE the existing "Statement of non-retraction" sub-section. Enumerates the §5.3 figure ref, the five new §6.x subsections, the §9.1 supplement, the Appendix A SHA addition, the F15-F22 figure pack pointer, and the rendered v0.4.1 PDF. Reaffirms that no v0.4 claim is retracted and section numbering is preserved.

## Constraints honored

- **Section numbering preserved.** §1-§4 and §6.1-§6.7 are untouched. Old §6.5 ("Why these targets matter") remains at the end of §6 after the new §6.8-§6.12 subsections (per the plan: §6.6 / §6.7 / §6.8-§6.12 ordering ahead of §6.5 was the existing convention in v0.4).
- **Engineering code untouched.** Text-only edits on the workspace-level master proposal.
- **F15-F22 figures are forthcoming.** All new subsections reference figures by ID only; rendering is the Wave 7B agent's scope.
- **No file overlap with other Wave 7 agents.** Only `01_master_proposal/` was touched here.
- **Commit SHAs cited are real.** Verified against `git -C .worktrees/integration log origin/stream/integration --oneline | head -20`:
  - `ca9e3af` — sanitize-check Rules 7/8/9 + 5 BLOCKING_PATTERNS for v0.4 (T-M4.2 eng); engineering tip
  - `c85233a` — Element X media JVM harness merge (M5.1b → M7 5/5)
  - `49bcdc9` — libavif native harness (M5.1b)
  - `4d03d7d` — libwebp WebPDecodeRGB harness (M3.1 — referenced from earlier integration history)
  - `68b8abd` — Signal LinkPreviewUtil JVM harness merge (M5.1)
  - `b4bdf4d` — matrix-rust-sdk Rust harness merge (M5.2)

## Verification grep commands

Run from the workspace root (or substitute `$PROP`):

```bash
PROP="/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md"
wc -l "$PROP"                           # expect ~1434 (v0.4 was 1225; +209 lines)
grep -c "v0.4.1" "$PROP"                # expect ≥11
grep -c "c14dc266" "$PROP"              # expect ≥2 (Appendix A + supplement table)
grep -c "ca9e3af" "$PROP"               # expect ≥6
grep -c "^### §6\." "$PROP"             # expect ≥7 (§6.6, §6.7, §6.8, §6.9, §6.10, §6.11, §6.12)
grep "^### §6\." "$PROP"                # confirm all five new §6.8-§6.12 subsections present
grep -c "INV-01" "$PROP"                # expect 1 (in §6.10 invariant table)
grep -c "C-DISC-V1" "$PROP"             # expect ≥1 (§6.12 limitation)
grep -c "AG-XSMA-VALIDATED" "$PROP"     # expect 1 (§6.11 limitation)
```

## Wave 7 coordination

- **Wave 7A (this agent):** master proposal v0.4 → v0.4.1 narrative.
- **Wave 7B (parallel):** F15-F22 figure pack rendering under `02_figures_and_storyboard/`. Subsections §6.8-§6.12 reference figures F17-F22 by ID; canonical .mmd sources + matplotlib fallback PNGs are 7B's deliverable.
- **Wave 7C (parallel):** submission-binder updates, `04_evidence/v0.4/` CETM bump to `ca9e3af`, `phase-ii-readiness/` refresh.
- **Wave 7-merge (sequential, after 7A+7B+7C):** PDF render of v0.4.1 master proposal to `06_rendered_outputs/`; cross-checks.

## Files changed in this wave

- `03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.4.md` (workspace-level; NOT in any git repo)
- `.worktrees/shared-public/PROPOSAL_V041_FINALIZATION_PASS.md` (this memo; committed to `stream/shared-public`)

No engineering code or schema files are modified.
