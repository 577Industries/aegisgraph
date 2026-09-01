# Phase 1 extraction — toolchain availability

This file documents which extraction tools are runnable in the current
research dev environment (the one this worktree was built on) and which are
deferred until the AegisGraph devcontainer is provisioned.

The Phase 1 extraction pipeline is *reproducible* in the devcontainer; in
the current host env, partial outputs are emitted with honest
`tool_run_status` markers — they are NOT phase 0 placeholders.

## Toolchain matrix

| Tool | Source-of-truth committed | Runnable now (host) | Runnable in devcontainer | Used to build current `extraction/output/*/graph.json`? |
|---|---|---|---|---|
| AegisGraph SMA CodeQL queries (8) | yes (`extraction/codeql/queries/*.ql`) | NO — `codeql` CLI absent | YES — pinned 2.26.4 | NO — emits `skipped_pending_toolchain` |
| Semgrep rules (4) | yes (`extraction/semgrep/rules/*.yml`) | YES — `semgrep` 1.157.0 in PATH; rules require target-source clone | YES | NO — clone of target source not present in this worktree |
| AndroidManifest analyzer | yes (`extraction/manifest/manifest_analyzer.py`) | YES — pure Python with lxml; needs target-source clone for real input | YES | NO — clone of target source not present; analyzer is exercised by `tests/test_extraction_manifest_analyzer.py` |
| MobSF runner | yes (`extraction/mobsf/run_mobsf.py`, `Dockerfile`) | NO — Docker present but MobSF image not pulled; APK acquisition requires F-Droid network | YES | NO — emits `skipped_pending_toolchain` |
| `build_db.sh` (Signal/Element-X) | yes (`extraction/targets/<target>/build_db.sh`) | NO — needs CodeQL CLI + JDK + Gradle | YES | NO |

## Adapters (Python, always runnable)

The four adapters under `extraction/adapters/` are pure Python and run in
every environment:

- `codeql_to_graph.py` — exercised by `tests/test_extraction_adapters.py`
- `semgrep_to_graph.py` — exercised by tests
- `manifest_to_graph.py` — exercised by tests
- `mobsf_to_graph.py` — exercised by tests
- `assemble.py` — exercised by `tests/test_extraction_no_anchor_only.py` and by `aegisgraph/extraction.py:run_extract`

## Current per-target evidence_source breakdown

When `make extract` is run on a host without target-source clones and
without CodeQL/MobSF, the resulting `extraction/output/<target>/graph.json`
contains records whose nodes carry:

- `evidence_source = "baseline_anchor_pending_toolchain:<sha256>"` — anchored
  to the pinned commit URL but pending a real tool run.

This is intentional and replaces the previous Phase 0 string
`"phase0 extraction placeholder, anchor-only"`. The Phase 0 string is now
forbidden in extraction output (enforced by
`tests/test_extraction_no_anchor_only.py`).

## How to upgrade to "ran" status

For each tool, run the corresponding step inside the devcontainer:

```bash
# CodeQL
extraction/targets/signal-android/build_db.sh
extraction/targets/element-x-android/build_db.sh
extraction/codeql/run_queries.sh signal
extraction/codeql/run_queries.sh element-x

# Semgrep (needs target source clone — done by build_db.sh)
TGT_SIGNAL="$(mktemp -d)"
git clone --depth=1 https://github.com/signalapp/Signal-Android "${TGT_SIGNAL}"
( cd "${TGT_SIGNAL}" && git checkout 1043851 )
semgrep --config extraction/semgrep/rules/ \
  --json --output extraction/output/signal/raw/semgrep.json \
  "${TGT_SIGNAL}"
rm -rf "${TGT_SIGNAL}"

# Manifest analyzer (same target clone applies)
python3 -m extraction.manifest.manifest_analyzer "${TGT_SIGNAL}" \
  --output extraction/output/signal/manifest-analysis.json

# MobSF — see extraction/mobsf/README.md for APK acquisition asymmetry.
python3 -m extraction.mobsf.run_mobsf signal --apk /path/to/signal.apk \
  --output extraction/output/signal/mobsf-results.json

# Re-assemble + commit only the normalized graph/coverage/manifest JSON.
make extract
```

After all four tools are `"ran"` for a target, `coverage.json` should
report `graph_evidence_ref_coverage >= 0.8` and the
`tests/test_extraction_coverage.py:test_full_toolchain_meets_strict_coverage`
test will be exercised when run with `AEGISGRAPH_FULL_TOOLCHAIN=1`.
