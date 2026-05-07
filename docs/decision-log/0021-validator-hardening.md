# 0021 — Validator hardening: non-mutating mode, sanitize-check, traceability

Status: accepted

## Context

The integration stream landed the public-sanitized export with a human
authorization gate (`release_authorized` False unless
`AEGISGRAPH_RELEASE_AUTHORIZED=1` AND a sanitize-check passes). The
sanitize-check function `aegisgraph/export.py::_sanitize_check_passes`
was a stub returning False unconditionally, so the gate could never
flip even when an operator deliberately authorized release. That
stub was the single load-bearing line blocking the public release
pipeline; this ADR records the hardening that replaces it and the
adjacent governance the validator-export stream owns.

Three additional capabilities ride along:

1. **Non-mutating validator mode.** Third-party reviewers must be able
   to verify evidence without writing `validation-report.json` to disk
   (which mutates a tracked file). We add a `--non-mutating` flag and
   `AEGISGRAPH_VALIDATOR_NON_MUTATING=1` env override.

2. **Strict tooling consumed via CLI.** Integration provides
   `aegisgraph.tooling.evaluate_strict` against the canonical
   `REQUIRED_TOOLS` table. We expose it through
   `validator.cli strict-tooling --required <subset>` so CI workflows
   can enforce a partial pin set without re-listing pins.

3. **Traceability matrix.** `reports/traceability_matrix.{json,md}`
   joins SPEC.md headers, on-disk evidence files,
   `docs/proposal-claims-index.yml`, and `docs/dsip-requirements.yml`.
   Every active proposal claim must show on the matrix; missing
   evidence surfaces as `claim_without_evidence`; orphan evidence as
   `evidence_without_claim`.

## Decision

We add a `validator/` Python package with these modules:

| Module | Responsibility |
| --- | --- |
| `validator/__init__.py` | Marker; no eager imports of `aegisgraph` to keep circular imports impossible. |
| `validator/sanitize_check.py` | Forbidden-pattern + schema-aware scan of public-sanitized exports. Exposes `is_export_safe(path) -> bool` and `scan_export_tree(path) -> ScanReport`. Imports `aegisgraph.safety.BLOCKING_PATTERNS` lazily so a removed/broken `aegisgraph.safety` fails the scan closed. |
| `validator/validate_evidence.py` | Backwards-compatible drop-in for the legacy single-script entrypoint, plus `validate_repo_non_mutating()` that re-runs `aegisgraph.validation.validate_repo` logic without writing to disk. |
| `validator/traceability_matrix.py` | Parses `SPEC.md` headers, loads the two YAML indices, walks on-disk evidence; emits `reports/traceability_matrix.{json,md}`. |
| `validator/cli.py` | Subcommand dispatcher: `validate`, `strict-tooling`, `sanitize-check`, `traceability`. |

Rules in `sanitize_check`:

1. Forbidden filesystem-path / credential / private-key strings on path or
   in any text-readable file body
   (`private[-_]submission`, `corpora-private`, `/Users/`, `/home/`,
   `C:\\`, `api_key`, `bearer\s...`, `private_key`, `BEGIN PRIVATE KEY`,
   plus AWS access-key, GitHub PAT, JWT defenses).
2. Records with `claim_state == "accepted"` AND `disclosure_status` not
   in `{public_historical, patched_public, not_applicable}`.
3. Records with `finding_type == "novel_private_candidate"`.
4. Tool-output documents (any document with `tool_output_type`) where
   `safety_posture != "sanitized_candidate"`.
5. Records with non-empty `bytes_b64`, `payload`, `raw_bytes`, or
   `raw_reproducer` fields; OR any value matching
   `aegisgraph.safety.BLOCKING_PATTERNS`.
6. Records where `claim_state == "accepted"` AND
   `validation_task.status` is something other than `passing` (no
   static-only promotion).

The function `scan_export_tree(empty_tree)` deliberately fails closed
(empty export → `ok=False`).

## Patch to integration's `_sanitize_check_passes` stub

Per the validator-export stream contract, we cannot modify
`aegisgraph/export.py` directly. Integration must apply the following
diff on next merge to replace the stub with a lazy import of
`validator.sanitize_check.is_export_safe`. The diff is intentionally
minimal — only the body of `_sanitize_check_passes` changes; the
calling contract (signature, exception posture, fail-closed default)
is preserved.

```diff
--- a/aegisgraph/export.py
+++ b/aegisgraph/export.py
@@
-def _sanitize_check_passes(root: Path) -> bool:  # pragma: no cover - stub
-    """Stub for the validator-export stream's sanitize check.
-
-    Returns False unconditionally until validator/sanitize_check.py lands.
-    The validator-export stream replaces this body with a real call:
-        from validator.sanitize_check import scan_public_export
-        return scan_public_export(root / "exports" / "public-sanitized").ok
-
-    Keeping the stub here (rather than at import time) means the export
-    module can be imported and unit-tested in isolation.
-    """
-    return False
+def _sanitize_check_passes(root: Path) -> bool:
+    """Real sanitize-check, replaces the integration stub.
+
+    Lazily imports validator.sanitize_check.is_export_safe so this module
+    stays importable in environments where the validator package is not
+    on sys.path (e.g. a stripped tarball of aegisgraph/ alone). On import
+    error the function returns False — fail-closed, matching the
+    pre-replacement contract.
+
+    Pointed at `<root>/exports/public-sanitized/` per the integration
+    stream's contract (see docs/decision-log/0011-public-export-human-gate.md).
+
+    See docs/decision-log/0021-validator-hardening.md for the rationale.
+    """
+    try:
+        from validator.sanitize_check import is_export_safe  # noqa: PLC0415
+    except Exception:
+        # Import failure (validator/ removed, syntax error in module,
+        # etc.) MUST stay fail-closed. Returning False keeps
+        # release_authorized at False even if the operator sets
+        # AEGISGRAPH_RELEASE_AUTHORIZED=1.
+        return False
+    try:
+        return bool(is_export_safe(root / "exports" / "public-sanitized"))
+    except Exception:
+        # is_export_safe is documented to never raise, but we add a
+        # defensive catch here too. Any exception → fail-closed.
+        return False
```

After integration applies this diff, the export contract becomes:

| Env / sanitize-check state | release_authorized | release_note |
| --- | --- | --- |
| Env unset OR sanitize FAIL | False | "Human authorization gate not yet wired …" or "AEGISGRAPH_RELEASE_AUTHORIZED=1 set, but validator/sanitize_check.py … did not pass." |
| Env=1 AND sanitize PASS    | True  | "Both environment authorization and sanitize-check passed; this manifest may be promoted by the operator after a final human review." |

Until integration applies the diff, the existing
`tests/test_export_private_complete.py` continues to assert
`release_authorized=False` even with `AEGISGRAPH_RELEASE_AUTHORIZED=1`,
because the stub still returns False. After the diff lands, integration
must update that test to (a) seed `exports/public-sanitized/` with the
real sanitized polydiff report (already produced by `export_public_sanitized`
non-dry), (b) set the env var, and (c) assert `release_authorized=True`.

## Why a separate `validator/` package?

- The integration stream's `aegisgraph/` is the runtime; `validator/`
  is the auditor. Mixing them risks the runtime importing the auditor
  during normal evidence runs, which would (a) drag YAML / SPEC parsing
  into the data path and (b) blur ownership during multi-stream
  reviews. Keeping them separate also makes it cheap to vendor
  `validator/` as a stand-alone audit tool for external reviewers.

- A circular import between `aegisgraph.export` and
  `validator.sanitize_check` is avoided by making `aegisgraph.export`
  lazily import `validator.sanitize_check.is_export_safe` only inside
  `_sanitize_check_passes`. We do NOT lift that import to module top —
  the lazy form keeps `aegisgraph.export` importable even if
  `validator/` is missing or broken.

## Why fail-closed on missing `aegisgraph.safety`?

`sanitize_check` Rule 5 requires the canonical `BLOCKING_PATTERNS`
regex set from `aegisgraph.safety`. If that import fails, we record a
synthetic `aegisgraph_safety_unavailable` failure and return
`ok=False`. Pretending success when half the rules are uncheckable
would be a silent disclosure-leak vector.

## Traceability rules

A claim is `ok` iff every artifact in `evidence_artifacts` exists on
disk **and** the claim has a `dsip_requirement` or non-null
`evidence_record`. A claim is `claim_without_evidence` if any listed
artifact is missing on disk, or if the claim has no `evidence_record`
and no artifacts. Claims with `owner_section: sbir_application` are
treated as `planned` (human-owned, not auto-substantiable).

`evidence_without_claim` rows surface on-disk artifacts under known
spec sections (4 ReproChain, 5 PolyDiff, 6 Extraction, 7 SMABench, 8
schema, 10 verification) that no claim references. These are
candidates for the proposal-package agent to either tie back to a
claim or retire.

`claim_without_evidence` rows in the v0.3 master are EXPECTED for the
following streams that have not merged into validator-export yet:

- ReproChain harness build & ASAN-confirmed run — owns
  `AG-CLAIM-V03-REPROCHAIN-LIBWEBP-CVE-2023-4863` and
  `AG-CLAIM-NOVEL-REPROCHAIN-PRE-DISCLOSURE`. Will satisfy once the
  reprochain stream lands `reprochain/evidence/build_manifest.json`
  in a non-blocked state.
- PolyDiff URL-parser corpus expansion — owns
  `AG-CLAIM-V03-POLYDIFF-REDISCOVERY-3` and
  `AG-CLAIM-NOVEL-POLYDIFF-FACT-VECTOR`. Today the regression set has
  3 deterministic disagreements; ≥3 historical-bug rediscoveries
  require the polydiff stream's expanded corpus.
- Recommendation contract bundling — owns
  `AG-CLAIM-METRIC-RECOMMENDATIONS-TWELVE`. The 12 recommendation
  records are described in §5.7 of the master proposal but are not
  yet emitted as JSON evidence files; the recommendation-bundling
  stream will land them.

These are recorded in `validator/MERGE_REQUEST.md` so the integration
reviewer can confirm the expected unbacked count matches.

## Tests

| Test | Asserts |
| --- | --- |
| `tests/test_validator_strict_tooling.py` | strict-tooling fails when a required tool is hidden from PATH |
| `tests/test_validator_sanitize_check.py` | sanitize-check fails on a fixture with `BEGIN PRIVATE KEY`; passes on a clean fixture |
| `tests/test_validator_non_mutating.py` | `validate --non-mutating` does not change `validation-report.json` mtime |
| `tests/test_traceability_matrix.py` | every active claim has ≥1 row; missing artifacts surface as `claim_without_evidence` |

## Consequences

- **Pro**: single-source sanitize ruleset; integration stream's gate
  flips correctly; third-party reviewers can verify without mutating
  tracked files; SPEC.md ↔ proposal claims ↔ DSIP requirements
  cross-referenced in one matrix.
- **Pro**: empty / missing export trees fail-closed; missing
  `aegisgraph.safety` fails-closed; broken validator imports
  fail-closed.
- **Con**: introduces a new top-level Python package the team must
  maintain; YAML schema in two doc files must stay in sync with the
  matrix join logic. Mitigation: traceability tests catch shape drift.
- **Con**: until ReproChain / PolyDiff / Recommendation streams merge,
  the matrix shows non-zero `claim_without_evidence` counts. This is
  expected and documented; reviewers should not block on it.

## Related ADRs

- 0010 — schema additive-only
- 0011 — public-export-human-gate (the gate this hardens)
- 0012 — integration merge-ready (the integration handoff)
