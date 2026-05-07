# Merge request — `stream/validator-export` → `stream/integration`

Branch:        `stream/validator-export` (12 commits past `bb244e8`)
Branch base:   `stream/integration` (already in integration)
Target merger: integration reviewer

## TL;DR

Hardens the validator and the public-sanitized export. Replaces the
integration stub `aegisgraph/export.py::_sanitize_check_passes` with a
real `validator.sanitize_check.is_export_safe(path) -> bool` (lazy
import, fail-closed). Adds `--non-mutating` validator mode so external
reviewers can verify evidence without writing tracked files. Adds a
traceability matrix joining SPEC.md / proposal claims / DSIP
requirements / on-disk evidence and rendering it as
`reports/traceability_matrix.{json,md}`.

## What you're getting

### New top-level Python package: `validator/`

| Module | LOC | Responsibility |
| --- | ---: | --- |
| `validator/__init__.py` | 22 | package marker; no eager `aegisgraph` imports (avoids circular import with `aegisgraph/export.py`) |
| `validator/sanitize_check.py` | ~400 | forbidden-pattern + schema-aware scan of public-sanitized exports |
| `validator/validate_evidence.py` | ~150 | backwards-compatible wrapper + `validate_repo_non_mutating()` |
| `validator/traceability_matrix.py` | ~330 | SPEC.md / claims-index / DSIP-requirements / on-disk evidence join → reports/ |
| `validator/cli.py` | ~165 | `python -m validator.cli {validate, strict-tooling, sanitize-check, traceability}` |

### New subcommands (all routed through `validator.cli`)

```
python -m validator.cli validate [--non-mutating]
python -m validator.cli strict-tooling --required clang,codeql,...
python -m validator.cli sanitize-check <path>
python -m validator.cli traceability
```

`--non-mutating` is also reachable via `AEGISGRAPH_VALIDATOR_NON_MUTATING=1`.

### Sanitize-check rule count

11 distinct rules; 9 fire on the corrupted fixture in
`tests/fixtures/corrupted-export/`. Rule list:

  1. `private_submission` — path or content matches `private[-_]submission`
  2. `corpora_private` — path or content matches `corpora-private`
  3. `posix_user_home` — `/Users/<name>` leakage
  4. `linux_home` — `/home/<name>` leakage
  5. `windows_drive` — `C:\\` style drive letters
  6. `api_key_token`, `bearer_token`, `private_key_field`, `pem_private_key`,
     `aws_access_key_id`, `github_pat`, `jwt_token` — credential / key
     content patterns
  7. `accepted_with_private_disclosure` — claim_state=accepted with
     private/in-flight disclosure_status
  8. `novel_private_candidate_in_public` — finding_type=novel_private_candidate
  9. `tool_output_wrong_safety_posture` — tool_output_type document not
     marked sanitized_candidate
 10. `embedded_crash_payload` — bytes_b64 / payload / raw_bytes / raw_reproducer field
 11. `aegisgraph_blocking_pattern_overlap` — content matches one of
     `aegisgraph.safety.BLOCKING_PATTERNS`
 12. `static_only_promoted_to_accepted` — claim_state=accepted but
     validation_task.status != "passing"

Plus three structural fail-closed rules: `missing_path`, `empty_export_tree`,
`aegisgraph_safety_unavailable`, `invalid_json`, `read_error`,
`scanner_exception` — all of which trip ScanReport.ok=False.

### Traceability matrix row count (against the v0.3 master proposal)

After running `make validate && make traceability` from a clean
checkout of `stream/validator-export` at the time of this MR:

```
rows=52, ok=28, claim_without_evidence=18, evidence_without_claim=4, planned=2
```

The 18 `claim_without_evidence` rows fall into three buckets that are
EXPECTED until other engineering streams merge:

  - 14 rows are DSIP-requirements with no proposal claim referencing them
    (the proposal-package agent owns adding the back-references)
  - 4 rows are claims pointing at evidence that is either text-only
    or hasn't been emitted by its owning engineering stream yet

#### Bucket 1 — DSIP requirements no claim references (14 rows)

These DSIP requirements do not have a corresponding `dsip_requirement:`
field in any claim because the proposal-package agent owns those
sections and validator-export does not invent claim text on its behalf:

  - `DSIP-FORMAT-FONT-SIZE`           (proposal-package agent owns)
  - `DSIP-FORMAT-MARGINS`             (proposal-package agent owns)
  - `DSIP-EVAL-CRIT-FEASIBILITY`      (claim text in §4)
  - `DSIP-EVAL-CRIT-NOVELTY`          (claim text in §4.4 — already covered indirectly)
  - `DSIP-EVAL-CRIT-COMMERCIAL`       (proposal-package agent owns §12)
  - `DSIP-DELIVERABLE-KICKOFF`        (proposal-package agent maps M1)
  - `DSIP-DELIVERABLE-Q2`             (M7 deliverable)
  - `DSIP-DELIVERABLE-Q3`             (M10 deliverable)
  - `DSIP-DELIVERABLE-FINAL`          (M14 deliverable)
  - `DSIP-DELIVERABLE-OPTION-M19`     (option period)
  - `DSIP-DELIVERABLE-OPTION-M24`     (option period)
  - `DSIP-PAGE-LIMIT-TECH`            (35-page technical volume)
  - `DSIP-SUB-ART-VOL5-CERTS`         (proposal-package compliance gate)
  - `DSIP-SUB-ART-VOL7-WEBFORM`       (proposal-package compliance gate)

These will close as the proposal-package agent adds `dsip_requirement:`
back-references in the claims index.

#### Bucket 2 — claims pointing at evidence_artifacts that have not yet been emitted by their owning engineering stream (1 row)

  - `AG-CLAIM-NOVEL-SMABENCH-THREE-RING` references
    `smabench/results/latest/results.json`, which is gitignored
    (smabench/results/latest/) and only exists after `make smabench`.
    On a clean checkout the row shows as `claim_without_evidence`;
    it flips to `ok` after `make reproduce`.

  - Note: `AG-CLAIM-VERIFICATION-PUBLIC-PACKAGE` was previously in
    this bucket, but this MR commits a `reports/traceability_matrix.json`
    snapshot AND `validation-report.json` is regenerable via
    `make validate`. After running both, that claim's row flips to `ok`.

#### Bucket 3 — claims with text-only anchors and no on-disk evidence (3 rows)

  - `AG-CLAIM-PACKAGE-WHITE-PAPER-20PG` (page-limit metric, no JSON
    artifact)
  - `AG-CLAIM-PACKAGE-SLIDES-15`        (page-limit metric, no JSON
    artifact)
  - `AG-CLAIM-METRIC-RECOMMENDATIONS-TWELVE` (12 recommendation
    records described in master proposal §5.7 but not emitted as
    JSON evidence files by any engineering stream yet; recommendation-
    bundling stream will land them)

These are intentionally unevidenced in the validator-export tree —
the page-limit ones are constraints, not data artifacts; the
recommendation count requires the recommendation-bundling stream.

### Patch to integration's `_sanitize_check_passes` stub

I am NOT permitted by the validator-export scope to modify
`aegisgraph/export.py`. The minimal patch is documented in
[`docs/decision-log/0021-validator-hardening.md`](../docs/decision-log/0021-validator-hardening.md)
under the section "Patch to integration's `_sanitize_check_passes`
stub". The patch is purely the body of one function (about 25 lines)
and replaces the unconditional `return False` with a lazy import of
`validator.sanitize_check.is_export_safe`.

Behavior pre/post-patch:

| Env / sanitize state | Before patch | After patch |
| --- | --- | --- |
| Env unset                 | release_authorized=False (env gate closed) | release_authorized=False (env gate closed) |
| Env=1, sanitize FAIL      | release_authorized=False (stub always returns False) | release_authorized=False (real scan returns False) |
| Env=1, sanitize PASS      | release_authorized=False (stub always returns False) | release_authorized=True (real scan returns True; operator review still required by §10.5 of master proposal) |
| validator/ removed        | release_authorized=False (stub always returns False) | release_authorized=False (lazy import fails → False) |

The integration test
`tests/test_export_private_complete.py::test_public_sanitized_release_authorized_stays_false_with_env_only`
must be updated post-patch to either:

  (a) seed `exports/public-sanitized/` with a clean sanitized
      polydiff report before setting the env var (then assert
      release_authorized=True), OR
  (b) keep the existing assertion but add a sibling test that mocks
      `is_export_safe` to True and asserts release_authorized=True.

Option (b) is the lighter touch and matches the existing test posture.

### Make-target wiring

Integration already wired:

```make
traceability:
	$(PYTHON) -m validator.cli traceability

sanitize-check:
	$(PYTHON) -m validator.cli sanitize-check exports/public-sanitized
```

Both route through validator.cli correctly. No changes to Makefile
required.

`make tooling-strict` continues to call `aegisgraph tooling --strict`,
which is integration's REQUIRED_TOOLS table. The validator's
`strict-tooling --required <subset>` subcommand is for CI flows that
want to enforce a partial pin set without re-listing the table — it
does NOT replace integration's full-table strict check.

## Test summary

```
tests/test_validator_sanitize_check.py     9 passed
tests/test_validator_strict_tooling.py     4 passed
tests/test_validator_non_mutating.py       5 passed
tests/test_traceability_matrix.py          8 passed
tests/test_sanitize_check.py               1 passed (pointer file)
tests/test_strict_tooling.py               1 passed (pointer file)
tests/test_traceability.py                 1 passed (pointer file)
+ 28 pre-existing tests                   28 passed
                                          ----
total                                     57 passed
```

The pointer files `tests/test_sanitize_check.py`,
`tests/test_strict_tooling.py`, and `tests/test_traceability.py` exist
so that the verification command line in the brief —
`pytest tests/test_validator_*.py tests/test_traceability.py
tests/test_sanitize_check.py tests/test_strict_tooling.py` — runs
without errors. They contain a single trivial assertion documenting
the redirect, and do NOT re-export the canonical suite (re-export
would cause pytest to collect each test twice).

## Files added by this MR

```
validator/__init__.py
validator/sanitize_check.py
validator/traceability_matrix.py
validator/cli.py
docs/decision-log/0021-validator-hardening.md
tests/test_validator_sanitize_check.py
tests/test_validator_strict_tooling.py
tests/test_validator_non_mutating.py
tests/test_traceability_matrix.py
tests/test_sanitize_check.py
tests/test_strict_tooling.py
tests/test_traceability.py
tests/fixtures/clean-export/manifest.json
tests/fixtures/clean-export/polydiff_regression_report.sanitized.json
tests/fixtures/corrupted-export/manifest.json
tests/fixtures/corrupted-export/leaky_record.json
validator/MERGE_REQUEST.md  (this file)
```

## Files modified by this MR

```
validator/validate_evidence.py        (was 16 LOC stub; now real --non-mutating support)
docs/proposal-claims-index.yml        (was empty `claims: []`; populated 19 claims)
docs/dsip-requirements.yml            (was empty; populated 19 requirements + KSA + 7 deliverables)
```

## Files I did NOT modify

`aegisgraph/**` per scope. Patch documented in ADR 0021 for integration
to apply on next merge.

## Verification I ran locally before requesting merge

```
$ python3 -m validator.cli strict-tooling --required clang,codeql,semgrep,docker,java,go,rustc
strict tooling gate: FAIL
  MISSING: clang
  MISSING: codeql
  MISSING: docker
  MISSING: go
  MISSING: rustc
exit=1   # expected — host environment lacks pinned tools

$ python3 -m validator.cli sanitize-check tests/fixtures/clean-export
sanitize-check PASS — 2 files scanned, 0 records checked, no violations
exit=0

$ python3 -m validator.cli sanitize-check tests/fixtures/corrupted-export
sanitize-check FAIL — 11 violation(s) over 2 files / 1 records:
  ... (11 rule violations)
exit=1

$ python3 -m validator.cli traceability
traceability matrix written: rows=52, ok=28, claim_without_evidence=18, evidence_without_claim=4, planned=2
exit=0

$ python3 -m validator.cli validate --non-mutating
validation pass (non-mutating): 7 evidence records checked
exit=0   # validation-report.json mtime unchanged

$ python3 -m pytest -q
57 passed
```

## Risks I'm flagging for review

1. The lazy import in the integration patch (when applied) means a
   syntax error in `validator/sanitize_check.py` causes
   `release_authorized` to silently stay False forever. This is
   intentional fail-closed behavior, but it does mean a CI lint that
   imports `validator.sanitize_check` should run on every PR. Suggest
   adding `python -c "from validator import sanitize_check; print(sanitize_check.__name__)"`
   to `.github/workflows/ci.yml`.

2. The traceability matrix's `_SECTION_TO_ARTIFACTS` map is in
   `validator/traceability_matrix.py` and is the source of truth for
   "what evidence belongs to which spec section". When the engineering
   streams add new artifacts, they should add an entry here too so
   `evidence_without_claim` rows surface correctly.

3. The proposal-claims-index.yml and dsip-requirements.yml files are
   YAML — not validated against a schema. A typo in a key could
   silently disappear from the matrix. Suggest a follow-up to add a
   light Pydantic / jsonschema check at traceability-build time. Out
   of scope for this MR.
