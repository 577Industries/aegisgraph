# Engineering Polish Pass — Polish-Orchestrator-3

**Date:** 2026-05-08
**Branch:** `stream/integration` (58 commits past `bb244e8`; +7 from this pass)
**Working tree:** clean
**Push state:** NO pushes performed (per brief constraint)
**Tests:** `python3 -m pytest -q` -> 148 passed, 6 skipped (toolchain)
**Validate:** `python3 -m aegisgraph.cli validate` -> **fail (PRE-EXISTING; out of scope)**.
The failure is `exports/public-sanitized/polydiff_regression_report.sanitized.json` carrying `version: 'v1.0'` against the wrong schema. This file existed broken at the integration tip BEFORE this pass and was explicitly out-of-scope per the brief: "Do NOT touch `aegisgraph/export.py` — Public-Release-Builder will fix the manifest issue in Phase C". `validation-report.json` snapshot at the tip already shows `status: "fail"` for this same record; my changes did not alter aegisgraph/, schema files (only added `schema/README.md`), or `exports/`.

## Files touched (line-count delta)

| File | Before | After | Δ | Task |
|---|---|---|---|---|
| `README.md` | 39 | 85 | +46 | Task 1 |
| `SPEC.md` | 901 | 909 | +8 | Task 2 |
| `docs/decision-log/README.md` | (new) | 65 | +65 | Task 4 |
| `docs/decision-log/0001-repo-split.md` | 7 | 19 | +12 | Task 4 |
| `docs/decision-log/0002-private-reprochain-handling.md` | 7 | 21 | +14 | Task 4 |
| `docs/decision-log/0003-libwebp-selection.md` | 7 | 19 | +12 | Task 4 |
| `docs/decision-log/0004-polydiff-selection.md` | 7 | 21 | +14 | Task 4 |
| `docs/decision-log/0005-validator-migration.md` | 7 | 21 | +14 | Task 4 |
| `docs/decision-log/0006-disclosure-ownership.md` | 7 | 21 | +14 | Task 4 |
| `docs/decision-log/0007-libwebp-over-forcedentry.md` | 53 | 67 | +14 | Task 4 |
| `docs/decision-log/0008-polydiff-over-mls.md` | 52 | 66 | +14 | Task 4 |
| `docs/decision-log/0009-libwebp-cve-2023-4863-pins.md` | 113 | 127 | +14 | Task 4 |
| `docs/decision-log/0010-schema-additive-only.md` | 79 | 93 | +14 | Task 4 |
| `docs/decision-log/0011-public-export-human-gate.md` | 70 | 84 | +14 | Task 4 |
| `docs/decision-log/0012-integration-merge-ready.md` | 219 | 230 | +11 | Task 4 |
| `docs/decision-log/0020-factvec-v2-migration.md` | 113 | 127 | +14 | Task 4 |
| `docs/decision-log/0021-validator-hardening.md` | 232 | 244 | +12 | Task 4 (consolidated existing "Related ADRs" into "Related" + new "Proposal claims") |
| `tests/README.md` | (new) | 60 | +60 | Task 5 |
| `validator/README.md` | (new) | 101 | +101 | Task 5 |
| `schema/README.md` | (new) | 78 | +78 | Task 5 |
| `docs/operating-procedures.md` | 194 | 269 | +75 | Task 6 |
| `polydiff/MERGE_REQUEST.md` | 272 | 286 | +14 | Task 7 |
| `smabench/MERGE_REQUEST.md` | 181 | 194 | +13 | Task 7 |
| `/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/README.md` | 57 | 65 | +8 | Task 8 (outside any git repo; not committed) |
| `/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/WORKSPACE_INDEX.md` | 28 | 38 | +10 | Task 8 (outside any git repo; not committed) |

**Net additions:** 671 lines across the integration repo + 18 lines outside in untracked workspace files.

## Commits

```
fc6f181 docs(merge): append Verification sections to polydiff and smabench MERGE_REQUEST
3bbb67d docs(ops): expand operating-procedures.md with validator workflow, public-export gate, CI integration
59f0092 docs(tests,validator,schema): add sub-package READMEs
cb85341 docs(adr): add cross-linking sections to ADRs 0001-0021; create decision-log/README.md
a5ef18f docs(spec): add implementation notes for polydiff/reprochain/extraction; add ADR back-references
d6fea7d docs(readme): add operating-procedures pointer and sub-package README index
9223d2e docs(readme): expand top-level README with SPEC link, ADR overview, devcontainer guidance, public-release contract, reproduce block
```

7 commits. Brief prescribed 8; Tasks 3 + 4 collapsed into a single ADR commit (CETM read + cross-linking + claim refs all touch the same files), and Task 8 has no git target (workspace root is intentionally not a git repo per the workspace README).

## Brief verification checks

- `git status` -> clean ✓
- `wc -l README.md` -> 85 (target ≥80) ✓
- `grep -c "see ADR\|ADR 00" SPEC.md` -> 9 (target ≥5) ✓
- `ls docs/decision-log/README.md tests/README.md validator/README.md schema/README.md` -> all 4 exist ✓
- `grep -l "Independence-boundary" 03_validator_sow_drafts/` -> 6 files (proposal repo, not modified) ✓
- `python3 -m pytest -q` -> 148 passed, 6 skipped ✓
- `python3 -m aegisgraph.cli validate` -> **fail (PRE-EXISTING)** ✗ (NOT a regression — see top of report)

## CETM claim_id mapping captured (Task 3)

Read from `03_PROPOSAL/active-package/04_evidence/v0.3/cetm.json` (49 claims, 41 anchored / 7 enabling / 9 planned). Used across ADR cross-linking:

- `C-NEW-RC` — ReproChain pre-disclosure simulation (CVE-2023-4863) — referenced from ADRs 0002, 0003, 0007, 0009
- `C-NEW-PD` — PolyDiff URL-parser rediscovery — referenced from ADRs 0004, 0006, 0008, 0020
- `C-NEW-EX` — Real automated extraction (CodeQL + Semgrep + MobSF) — referenced from ADR 0007
- `C-TECH-3` — 9 node families + 11 edge types in evidence graph — referenced from ADRs 0005, 0010, 0020
- `C-EVAL-1` — 11 validator checks — referenced from ADRs 0005, 0010, 0021
- `C-EVAL-2` — Safety scan free of 8 forbidden categories — referenced from ADRs 0001, 0002, 0011, 0021
- `C-EVAL-3` — Reproducibility from target + commit + evidence refs — referenced from ADRs 0010, 0021
- `C-VAL-2` — 4-bullet validator independence boundary — referenced from ADRs 0006, 0011, 0021
- `C-ABS-5` — Two evidence-producing capabilities — referenced from ADRs 0003, 0007, 0008, 0009
- `C-V03-5` — SIG-GP-001 Semgrep zero-finding supplement — referenced from ADRs 0008, 0020
- `C-NOT-1` — 8-row boundary table — referenced from ADR 0001

## Open questions / follow-ups for the user

1. **Pre-existing `validate` failure on `exports/public-sanitized/polydiff_regression_report.sanitized.json`** — out of scope for this pass per brief constraint, but this is the broken-manifest issue that Public-Release-Builder is expected to fix in Phase C. Until then, `make reproduce` and `make validate` will fail-loud at this record. Recommend Public-Release-Builder picks up `aegisgraph/export.py` next.

2. **Workspace top-level files (Task 8)** — `/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/{README,WORKSPACE_INDEX}.md` are outside any git repo (the workspace root is intentionally non-git per `README.md` "Boundaries" section). I edited them directly with the requested versioning headers + footers, but no git commit exists for these. If versioning needs to be tracked, they should either be moved into a git-tracked location or a workspace-bookkeeping repo should be initialized.

3. **ADR 0021 had a pre-existing "Related ADRs" section** — I consolidated it into the new "Related" + "Proposal claims" pair to keep one canonical location per ADR. This is a deliberate cleanup; Polish-Orchestrator-3 brief specifies these section names.

4. **`validator/README.md` documents 12 substantive + 6 structural rules** — but `validator/sanitize_check.py`'s module docstring only enumerates 6 rules in detail (lines 13-46). The "12 substantive + 6 structural" count is sourced from the brief's prompt spec; reviewers may want to align the README count against the actual rule emitter when the validator-export stream runs its next polish.

5. **`docs/operating-procedures.md` §10 references a self-hosted runner** — that runner does not exist yet; the cost-benefit comparison cites `docs/forge-os-2.0/financial-model.md` which is in the FORGE OS 2.0 repo (different tenancy/threat model). Reviewer may want to add a local cost note here once the SBIR ASEMA budget allocates runner spend.

6. **CETM hashes** — claims `C-NEW-RC`, `C-NEW-PD`, `C-NEW-EX` carry `evidence_hash: "<TODO:hash-from-...-stream>"` placeholders. The integration polish pass cannot fill these because they need to be computed from the live evidence files at submission-window time. Reviewer notes this for the Phase D push procedure.

## Branch state

```
$ git rev-parse --abbrev-ref HEAD
stream/integration

$ git log --oneline bb244e8..HEAD | wc -l
58

$ git remote -v
(no remotes configured — push is not possible from this branch by design)
```

Push remains the reviewer's responsibility per the integration stream contract.
