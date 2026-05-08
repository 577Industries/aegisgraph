# AegisGraph Test Suite

Test layout, ownership, and how to add tests.

## Layout

Tests live in `tests/` at the repo root. They are organized by stream:

- `test_validation_e2e.py`, `test_e2e_reproduce.py` — integration agent (smoke + end-to-end reproduce)
- `test_schema_validation.py` — integration agent (all 6 + 1 proposed schemas; per-schema Draft 2020-12 conformance + baseline-presence guard)
- `test_export_private_complete.py` — integration agent (private-export contracts; release_authorized fail-closed semantics)
- `test_smabench.py`, `test_smabench_repeatability.py`, `test_smabench_ring1_real_corpora.py`, `test_smabench_ring2_reads_real_extraction.py` — smabench-harness stream
- `test_polydiff.py`, `test_polydiff_disagreement_axes.py`, `test_polydiff_factvec_v2_schema.py`, `test_polydiff_regression_count.py`, `test_polydiff_wrappers_smoke.py` — polydiff-core stream
- `test_reprochain_build.py`, `test_reprochain_run_summary.py`, `test_reprochain_mapping_records.py` — reprochain-proof stream
- `test_extraction_adapters.py`, `test_extraction_byte_stable.py`, `test_extraction_coverage.py`, `test_extraction_manifest_analyzer.py`, `test_extraction_mobsf_runner.py`, `test_extraction_no_anchor_only.py` — real-extraction stream
- `test_validator_non_mutating.py`, `test_validator_sanitize_check.py`, `test_validator_strict_tooling.py`, `test_sanitize_check.py`, `test_strict_tooling.py`, `test_traceability.py`, `test_traceability_matrix.py` — validator-export stream
- `test_claims.py`, `test_hashchain.py`, `test_safety.py` — Phase-0 baseline (unchanged across streams)

`tests/fixtures/` holds reference fixtures (e.g., the clean-export and corrupted-export fixtures for sanitize-check, the synthetic-Signal sync envelopes for smabench).

## Test gating

Some tests gate on environment variables. The defaults are honest about toolchain availability outside the pinned devcontainer:

- `AEGISGRAPH_FULL_TOOLCHAIN=1` — strict-coverage tests for extraction (gate on CodeQL CLI 2.20.6 + JDK 21 + Android SDK 34 availability). Without this flag, extraction coverage tests record `coverage=0.0` and pass against a `blocked_pending_toolchain` build status.
- `AEGISGRAPH_VALIDATOR_NON_MUTATING=1` — validator runs without writing `validation-report.json`. Used by CI / external reviewers who must not alter tracked files.
- `AEGISGRAPH_RELEASE_AUTHORIZED=1` — public-sanitized export gate. Works with `--dry-run` for tests that exercise the full export contract without writing files. See ADR 0011.
- `AEGISGRAPH_STRICT_TOOLING=1` — strict tooling check (CI mode). Without this, `make tooling-strict` exits 1 outside the devcontainer (intentional fail-closed).

## Skip patterns

Parsers / wrappers not built in the current host (Java/Rust/Go/Clang) skip cleanly with `pytest.skip()`. Run `python3 -m pytest -q` and expect ~5 skips on a host without the full toolchain. In the devcontainer, all skips drop to 0.

If you see a test fail rather than skip on a missing toolchain, that is a contract bug — file it under the relevant stream's MERGE_REQUEST follow-ups.

## Adding tests

1. New tests live in `tests/test_<stream>_<topic>.py` (e.g., `test_polydiff_userinfo_axis.py`, `test_extraction_javabytecode_adapter.py`).
2. Tests must be deterministic — no live network probes, no real cryptography, no production-app targeting. Synthetic fixtures only.
3. Reference fixtures via `tests/fixtures/` (e.g., the clean-export and corrupted-export fixtures for sanitize-check, the synthetic Signal sync envelopes for smabench).
4. Each new test gets a 1-line docstring explaining what contract it locks. Reviewers use this as the merge-request acceptance summary.
5. If a test requires a tool not in the devcontainer base, gate it on `AEGISGRAPH_FULL_TOOLCHAIN` (or a more specific flag) and document why in the docstring.

## Running

```
# Full suite, expect skips outside devcontainer
python3 -m pytest -q

# Single stream
python3 -m pytest -q tests/test_polydiff_*.py

# Single file
python3 -m pytest -q tests/test_polydiff_regression_count.py

# Strict mode (devcontainer or self-hosted runner)
AEGISGRAPH_FULL_TOOLCHAIN=1 python3 -m pytest -q
```

The `make test` target wraps the first form; CI runs the strict variant on a self-hosted runner once the runner is provisioned (see `.github/workflows/reproduce.yml` and `docs/operating-procedures.md` §10 for current state).
