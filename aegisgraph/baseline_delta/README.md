# `aegisgraph.baseline_delta` — Wave 9A / M14 deliverable

Per-tool baseline comparison: same threat surface (Signal Android
`@1043851` + Element X Android `@91d265e6`) scanned by **CodeQL alone**,
**Semgrep alone**, **MobSF alone**, and **AegisGraph** (15-invariant
library v3 + PolyDiff Extended regression). Produces a structured
`delta-report.{md,json}` whose headline column is **"added by
AegisGraph"** — findings AG surfaces that single-tool baselines miss at
the same `(target, category, location_hash)` coordinate.

This is the M14 demo-gate deliverable in the Phase II milestone table
(plan §5; see also `docs/decision-log/`):

> "Baseline-tool delta report (AegisGraph vs CodeQL alone vs Semgrep
>  alone vs MobSF)."

## What this package contains

```
aegisgraph/baseline_delta/
|-- __init__.py        # public sub-API (renderer, runner)
|-- runner.py          # per-tool subprocess orchestration
|-- renderer.py        # finding normalization + overlap matrix + delta
|-- Dockerfile         # pins CodeQL 2.20.6 + Semgrep 1.86 build env
`-- README.md          # this file
```

Tests live under `tests/baseline_delta/`:

  * `test_runner_skips_if_binary_absent.py` — runners emit
    `binary_missing` / `apk_missing` envelopes when CLI tools are not
    on PATH. No silent failures.
  * `test_renderer_overlap_matrix.py` — `compute_overlap_matrix`
    correctness on synthetic findings.
  * `test_renderer_added_by_aegisgraph_column.py` — the M14
    discovery-delta metric is computed correctly.
  * `test_mobsf_limited_path.py` — APK-absent path writes
    `MOBSF-LIMITED.md` with required fields; no fabricated findings.

A top-level guard `tests/test_baseline_delta_artifacts_present.py`
asserts the rendered report exists at the canonical path; it is
`skipif`-gated until the self-hosted runner has executed the workflow.

## Output tree

```
03_PROPOSAL/active-package/04_evidence/v0.4/baseline-tool-delta/
|-- signal_android/
|   |-- codeql-findings.json
|   |-- codeql-coverage.json
|   |-- semgrep-findings.json
|   |-- semgrep-coverage.json
|   |-- mobsf-findings.json      (or MOBSF-LIMITED.md when APK absent)
|   |-- aegisgraph-findings.json
|   `-- aegisgraph-coverage.json
|-- element_x_android/
|   `-- (same shape)
|-- delta-report.md              (human-readable summary)
|-- delta-report.json            (machine-readable)
`-- checksums.sha256             (atomic; regenerated after every full run)
```

## Constraints (load-bearing)

1. **Anchor-only.** Target source trees are pinned by commit hash and
   not redistributed in this research repo. The self-hosted runner
   clones them at execution time per
   `extraction/targets/<target>/build_db.sh`. No live target probing.
2. **APK absence is honest.** When MobSF cannot run because no APK is
   available, the runner writes `MOBSF-LIMITED.md` with the
   target_id, repo, commit, reason, and the anchor-only policy note.
   Findings count is zero; no fabricated findings are emitted.
3. **Sanitize-check Rule 7/8/9 compliant.** SARIF source snippets are
   NEVER propagated into the public records. Only `location_hash`
   fingerprints. Records emit through `aegisgraph.evidence.finalize_record`
   for AG records.
4. **Subprocess injection-safe.** Each runner accepts an injectable
   `which`/`subprocess_run` for tests; real production binaries are
   never executed in the unit-test suite.
5. **No file overlap.** This package does NOT touch
   `aegisgraph/workbench/`, `aegisgraph/crosssma/`, or
   `aegisgraph/disclosure/`. It is a standalone reporter.

## Tool version pins

| Tool | Pinned version | Source of truth |
|---|---|---|
| CodeQL CLI | 2.20.6 | `devcontainer/Dockerfile` |
| Semgrep | 1.86.0 | `aegisgraph/baseline_delta/Dockerfile` |
| MobSF | (digest captured at build time) | `extraction/mobsf/Dockerfile` |
| Python | 3.11 | engineering devcontainer |

## CI workflow

`.github/workflows/baseline-delta.yml` runs this package on a
self-hosted runner under `workflow_dispatch` only. It:

  1. Builds the Dockerfile here to lock the toolchain.
  2. Re-builds the CodeQL DBs for both targets (anchor-only) by
     invoking `extraction/targets/<target>/build_db.sh`.
  3. Runs each per-tool runner.
  4. Calls `aegisgraph.baseline_delta.renderer` to produce
     `delta-report.{md,json}`.
  5. Regenerates `checksums.sha256` atomically.
  6. Uploads the report artifacts (NOT the raw SARIF — Rule 8).

The workflow is manual-trigger so it cannot consume any user-supplied
input (no `pull_request_target`, no `issue_comment` triggers; only
`workflow_dispatch`).

## Honest scope

  * **Live execution** of CodeQL / Semgrep against pinned source trees,
    and live MobSF execution against staged APKs, requires the
    self-hosted runner (T-M4.1). On developer machines the test suite
    runs binary-agnostically (skip-on-absent semantics).
  * **AegisGraph "ran" output** depends on `extraction/output/<target>/`
    pre-existing consolidated invariant violations. On developer
    machines the AegisGraph runner returns `scaffold_pending` and emits
    an empty findings envelope — still a valid report row, but the
    delta column is zero until the runner builds the DBs.
  * **The report writes the v0.4 output tree by default.** The v1.0 cut
    (M14) replaces this with a final report; the v0.4 staging is the
    Phase II in-flight artifact.
