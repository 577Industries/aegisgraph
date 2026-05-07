# 0011 Public Export Human Authorization Gate

Status: accepted, integration stream owns enforcement.

## Decision

`exports/public-sanitized/manifest.json` ALWAYS emits
`release_authorized=False` until BOTH of these are true:

1. The operator has set `AEGISGRAPH_RELEASE_AUTHORIZED=1` in the
   environment that runs `aegisgraph export public-sanitized`.
2. `validator/sanitize_check.py` (validator-export stream) returns
   "pass" against the rendered `exports/public-sanitized/` tree.

The flag is `False` when EITHER condition fails. There is no condition
under which the flag flips automatically without the env var. There is
no condition under which the flag flips with only the env var (the
sanitize check must also pass).

## Rationale

A False `release_authorized` field is the load-bearing signal that the
sanitized export is a CANDIDATE, not an authorized release. Downstream
publishers (the operator who copies into `02_PUBLIC_RELEASE/`) refuse
to act on a manifest with `release_authorized=False`. Inverting this
default — even briefly, even in a test fixture — risks a candidate
manifest being treated as an authorized release.

We do NOT short-circuit through the env var alone. An accidental
`AEGISGRAPH_RELEASE_AUTHORIZED=1` in a CI runner, in a maintainer's
shell rc, or in a Make wrapper would otherwise produce
`release_authorized=True` on a candidate that has never been
sanitize-checked. The AND of two independent conditions makes that
class of mistake structurally impossible.

## Implementation status

- `aegisgraph/export.py::export_public_sanitized` reads
  `AEGISGRAPH_RELEASE_AUTHORIZED` and calls `_sanitize_check_passes`.
- `_sanitize_check_passes` is currently a STUB that returns False
  unconditionally. The validator-export stream replaces the stub with:
  ```python
  from validator.sanitize_check import scan_public_export
  return scan_public_export(root / "exports" / "public-sanitized").ok
  ```
- `tests/test_export_private_complete.py` covers four cases:
  default (False), env-only (still False), dry-run (no files written),
  real-run (manifest written).
- The `release_note` field tells the operator which condition failed,
  so a False value is self-documenting.

## What flips this decision

1. The validator-export stream lands `validator/sanitize_check.py` AND
   the integration stream replaces the stub with the real call. After
   that point, `release_authorized` may flip True for clean inputs.
   This ADR is updated, not retired.
2. The team decides to gate public release on additional human review
   (e.g., a PR-approval workflow that records the reviewer's name in
   the manifest). Adds a third AND clause; does not relax existing two.

## Out of scope

- This ADR does not govern the PRIVATE submission export
  (`exports/private-submission/manifest.json`). Private submissions go
  to DARPA reviewers under the DSIP terms and are NOT subject to this
  gate.
- This ADR does not specify what counts as "sanitized." That contract
  is defined in `validator/sanitize_check.py` (validator-export stream)
  and the patterns in `aegisgraph/safety.py::BLOCKING_PATTERNS`.
