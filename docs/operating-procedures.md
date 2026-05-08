# AegisGraph Tier 3 — Operating Procedures

This document is the day-to-day playbook for parallel-stream contributors,
the integration owner, and reviewers preparing the DARPA/ASEMA submission.
It is intentionally short. Long-form rationale lives in
`docs/decision-log/000X-*.md`; this file tells you what to *do*.

## 1. Stream → integration → daily-rebase loop

The repo runs five parallel research streams plus one integration owner:

| Stream | Branch prefix | Owner files |
|---|---|---|
| reprochain-proof | `stream/reprochain` | `reprochain/**` |
| real-extraction | `stream/extraction` | `extraction/**` |
| polydiff-core | `stream/polydiff` | `polydiff/**`, schema/fact-vector v2 proposals |
| smabench-harness | `stream/smabench` | `smabench/**` |
| validator-export | `stream/validator` | `validator/**`, traceability matrix populate |
| **integration**   | `stream/integration` | schema, aegisgraph/, Makefile, devcontainer/, ADRs, CI |

Each stream works in a worktree under `.worktrees/<stream>` (gitignored)
and pushes to its own branch. **Streams do NOT push to `main`.** Streams
do NOT push to each other. Only integration merges.

The daily loop:

1. **Start of day**: each stream rebases its branch onto `stream/integration`
   (NOT onto `main`). This pulls in any schema, helper, or ADR change that
   landed yesterday.

   ```
   git fetch origin
   git rebase origin/stream/integration
   ```

2. **End of day** (or on a logical commit boundary): stream owner pushes
   to its branch and opens a PR against `stream/integration`. The PR body
   must include the pre-merge checklist (§3 below).

3. **Integration owner** reviews and merges in the order listed in §4.
   Merge conflicts are the stream owner's responsibility unless they
   touch `aegisgraph/` or `schema/` — in which case the integration
   owner resolves and may write or update an ADR.

4. **Integration owner** rebuilds `stream/integration` after each merge
   and pushes. Stream owners pick up the new tip on their next rebase.

## 2. Schema-delta-via-PR-plus-ADR contract

Schema changes go through a stricter loop than code:

1. Fork `schema/<name>.schema.json` to `schema/<name>.schema.v2.proposed.json`
   if (and only if) the change is breaking. Per
   `docs/decision-log/0010-schema-additive-only.md`, additive changes go
   to the existing file.

2. Open an ADR under `docs/decision-log/` numbered consecutively
   (next free integer) with body following the template:

   ```
   # NNNN <Title>
   ## Decision
   ## Rationale
   ## Status
   ## Affected streams
   ## Migration plan (if applicable)
   ```

3. Submit the ADR + the schema change in the SAME PR. The schema is
   never merged without its ADR, and the ADR is never merged without
   the corresponding emitter change in `aegisgraph/` or in the relevant
   stream module.

4. Integration owner runs `make test` (verifies all schemas still pass
   `Draft202012Validator.check_schema()`) and `make validate` (verifies
   no record regresses) before accepting the merge.

## 3. Pre-merge checklist

Every PR into `stream/integration` (or directly into `main` for the
final integration → main bump) must satisfy:

- [ ] Branch is rebased onto current tip of `stream/integration`.
- [ ] `make test` passes locally (and in CI).
- [ ] `make validate` exits 0 with `status="pass"`.
- [ ] `make tooling-strict` passes locally OR the PR explicitly documents
  which pinned tools are absent and why CI's non-strict gate is still
  acceptable.
- [ ] No new `evidence_refs[*]` carries a raw reproducer or live-target
  output (statically: `git diff stream/integration..HEAD -- '*.json'`
  must not introduce `raw_bytes`, `payload_b64`, `nmap`, etc., outside
  intentional scanner-test fixtures).
- [ ] No file under `reprochain/corpora-private/` is committed.
- [ ] If the PR touches `schema/**`, an ADR is included (see §2).
- [ ] If the PR touches `aegisgraph/safety.py`, `aegisgraph/evidence.py`,
  `aegisgraph/export.py`, or any `validator/sanitize_check*`, the
  integration owner reviews the diff line-by-line. These four areas
  control whether unsafe records can leave the repo; their review bar
  is "no regressions, ever".
- [ ] Static-only findings are NOT promoted to vulnerability claims. A
  finding with `claim_state="accepted"` must have a passing
  `validation_task` whose `command` actually executes — and the limitation
  text must explain what was NOT validated.

## 4. Merge order

Integration applies merges in this order. Order exists to minimize token
churn and avoid validator/sanitize cascading rewrites.

1. **smabench-harness** first. It is the most isolated stream
   (corpus + scoring), it adds new files only, and it does not modify
   shared schema or helpers. Landing it first lets the polydiff stream
   reuse smabench's corpus shape.
2. **polydiff-core** second. It may propose `schema/fact-vector.schema.v2.proposed.json`;
   if so, the integration owner reviews the schema additive policy
   compliance before accepting. Polydiff's evidence records reference
   smabench corpora.
3. **reprochain-proof** third. ReproChain's evidence references the
   libwebp ADR (`docs/decision-log/0008-libwebp-cve-2023-4863-pins.md` —
   the integration stream creates the template; reprochain fills in the
   commit SHAs and signs). ReproChain's records may reference polydiff
   fact vectors as upstream evidence; landing polydiff first means
   reprochain doesn't need to fix dangling refs.
4. **real-extraction** fourth. Extraction emits the most evidence
   records; landing schema/helper/policy changes first means extraction
   does the work once, not twice.
5. **validator-export** last. It populates `docs/proposal-claims-index.yml`,
   `docs/dsip-requirements.yml`, and the traceability matrix; it
   implements `validator.sanitize_check` and `validator.cli traceability`.
   Landing it last means the matrix and sanitize check operate on the
   final emitter outputs from steps 1–4.

After each merge:
- Integration owner runs `make reproduce` end-to-end.
- If reproduce passes (status `pass`), integration owner pushes
  `stream/integration` and tags `stream/integration-after-<stream>`.
- If reproduce fails, integration owner reverts the merge and opens a
  blocker issue back to the stream owner with the failing record IDs.

## 5. Sanitize / public release

The public-sanitized export pipeline is **never** automated. Even with
all gates passing, the operator runs:

```
make sanitize-check                  # validator-export stream's gate
AEGISGRAPH_RELEASE_AUTHORIZED=1 \
    aegisgraph export public-sanitized --dry-run    # verify manifest
# review exports/public-sanitized/manifest.json by hand
AEGISGRAPH_RELEASE_AUTHORIZED=1 \
    aegisgraph export public-sanitized              # actually write
```

`release_authorized` flips True only when ALL of:
- `AEGISGRAPH_RELEASE_AUTHORIZED=1` is set
- `validator/sanitize_check.py` (validator-export stream) passes against
  the rendered tree
- A human has reviewed the manifest

Today (`stream/integration` first cut) condition (b) is unwired:
`_sanitize_check_passes` is a stub that returns False. This is
intentional fail-closed — see `docs/decision-log/0011-public-export-human-gate.md`.

## 6. Forbidden actions (kill-switch list)

If you find yourself doing any of these, stop:

- Pushing to `main` from a stream branch.
- Pushing to `02_PUBLIC_RELEASE/` or `03_PROPOSAL/` from this repo.
- Adding raw target source to `reprochain/vendor/` (vendored-library
  source is permitted only for libwebp under the BSD-3-Clause license,
  and only the harness-relevant subset).
- Live-target probing (no `nmap`, `masscan`, `sqlmap`, etc., against
  any production property — full enforcement list is in
  `aegisgraph/safety.py::BLOCKING_PATTERNS`).
- Promoting a static-only finding to `claim_state="accepted"` without
  a passing `validation_task` that demonstrates reachability.
- Skipping a pre-commit/PR hook with `--no-verify` or `--force`.
- Using `git push --force` against `stream/integration` or `main`.

## 7. Quality gates summary

These gates are run, in order, before any merge into `stream/integration`:

```
make tooling-strict   # devcontainer toolchain pin check
make test             # unit + integration tests
make validate         # schema + safety + hash-chain
make reproduce        # full pipeline (extracts, regression, smabench, validate)
```

If `make tooling-strict` fails locally because the maintainer is on a
non-devcontainer machine, that is acceptable for development; the same
command must pass on a self-hosted runner before final integration → main.

## 8. Validator workflow

`validator/cli.py` exposes four subcommands. See `validator/README.md` for the full reference; this section is the day-to-day operator playbook.

```
# Run schema + safety + hash-chain validation. Writes
# validation-report.json; fails on any record that does not validate.
python3 -m validator.cli validate

# Same, but does not write to disk. Used by external reviewers and CI
# in checkout-as-read-only mode. Equivalent to setting
# AEGISGRAPH_VALIDATOR_NON_MUTATING=1.
python3 -m validator.cli validate --non-mutating

# Probe a custom subset of pinned tools (the integration stream's
# REQUIRED_TOOLS table remains authoritative for `make reproduce`).
python3 -m validator.cli strict-tooling --required clang,codeql,semgrep,docker,java,go,rustc

# Scan a public-sanitized export tree (12 substantive + 6 structural
# rules). Exit 1 on any failure with one failure per line. Used by
# aegisgraph/export.py via lazy import and by sanitize.yml workflow.
python3 -m validator.cli sanitize-check exports/public-sanitized/

# Emit reports/traceability_matrix.{json,md} from SPEC.md headers,
# proposal-claims-index.yml, dsip-requirements.yml, and on-disk
# evidence files.
python3 -m validator.cli traceability
```

Expected outputs:

```
$ python3 -m validator.cli validate
status: pass — schemas=6 valid, records=N validated, hash-chain=ok

$ python3 -m validator.cli sanitize-check exports/public-sanitized/
status: ok (no failures)

$ python3 -m validator.cli traceability
[traceability] anchored=A unanchored=U
wrote reports/traceability_matrix.json
wrote reports/traceability_matrix.md
```

A non-zero `unanchored=U` count is expected during Phase 0 / Phase 1; reviewers should not block on it.

## 9. Public-export approval gate

The public-sanitized export pipeline is the single boundary between Tier-3 private research and the v0.3 public release. The flow is intentionally *not* automated, even when all gates pass.

1. Operator runs `make export-public-sanitized`. The Make target invokes `python3 -m aegisgraph.cli export public-sanitized` (without `AEGISGRAPH_RELEASE_AUTHORIZED`), producing `exports/public-sanitized/manifest.json` with `release_authorized=False`. No tarball is published.
2. PI reviews `04_REPORTS_AND_EXPORTS/handoff/RELEASE_APPROVAL.md`. The review covers (a) the manifest hash chain, (b) the SOTA matrix updates, (c) the limitation language on every record, and (d) the disclosure-status of every accepted finding.
3. PI signs (printed name, date, APPROVE) by editing `RELEASE_APPROVAL.md` and committing it to the integration branch. The signed file is the human-side evidence.
4. Operator sets `AEGISGRAPH_RELEASE_AUTHORIZED=1` and re-runs `python3 -m aegisgraph.cli export public-sanitized`. Now both gate conditions can flip: the env var is set AND `validator/sanitize_check.py` runs. If sanitize-check passes, `release_authorized=True`. If it fails, `release_authorized` stays False and `release_note` records which rule was violated.
5. Operator publishes per the Phase D push procedure: copy the resulting `exports/public-sanitized/*.tar.gz` to the public-release repo on a `release/v0.3.0` branch, push, open PR, merge after CI re-runs the sanitize-check on the rendered tarball.

The `release_authorized=False` default is structural — there is no condition under which the flag flips automatically without the env var; there is no condition under which it flips with only the env var (sanitize-check must also pass). See ADR 0011 for the rationale.

Today (`stream/integration` first cut + post-validator-export merge): the stub in `aegisgraph/export.py::_sanitize_check_passes` is replaced with the real `validator.sanitize_check.is_export_safe(...)` call (commit `f5f399a`). All four gate cases (default / env-only / dry-run / authorized-with-passing-check) are covered by `tests/test_export_private_complete.py`.

## 10. CI integration

Current state of `.github/workflows/`:

- **`ci.yml`** runs on every push and on PR. It executes `make tooling` (non-strict) + `make test` + the Python lint checks. It does NOT run `make reproduce` (that requires the pinned devcontainer; see below). Pass criteria: all unit + integration tests green; tooling versions written to `tooling-versions.json`.
- **`reproduce.yml`** is `if: false` until a self-hosted runner with the pinned devcontainer image is provisioned. The workflow body is correct; flipping `if: false` → `if: ${{ vars.SELF_HOSTED_AVAILABLE }}` (or similar) wires it on. Until then, `make reproduce` is run on a maintainer workstation before each integration → main bump and the result is recorded in `reports/reproduce-status.json`.
- **`sanitize.yml`** runs on `workflow_dispatch` only. It is the explicit operator-driven public-export gate: invoked manually after a sanitized export tarball is rendered, the workflow runs `python3 -m validator.cli sanitize-check` against the rendered tree and exits 1 on any failure. It does NOT run on push to avoid leaking sanitize-check failures to the public CI surface (failures are evidence; we treat them as private until reviewed).

Self-hosted runner roadmap:
- Requires CodeQL CLI 2.20.6, Clang 18 + libfuzzer-18, OpenJDK 21, Docker (for MobSF), Go 1.22.5, Rust 1.79.0, Node 20, Android SDK 34 + NDK r26d.
- Hardware: ≥16 vCPU, ≥32 GB RAM, ≥100 GB SSD (CodeQL databases are large for Signal Android + Element X Android).
- Cost-benefit: a single CodeQL build of Signal at the pinned commit takes ~25 min on a 16-vCPU runner. Weekly reproducibility CI = 100 min/week ≈ 7 hr/month of dedicated runner time. Cost-pending: decision on Hetzner CCX33 vs. GitHub-managed `larger` runners is open. See `docs/forge-os-2.0/financial-model.md` for the rough comparison; this VPS is **not** the same as the FORGE OS 2.0 prod VPS (different tenancy, different threat model).

Until the runner exists, the integration owner is responsible for running `make reproduce` on a maintainer workstation before any integration → main bump and recording the result in `reports/reproduce-status.json`. Drift is flagged in the next reviewer pass.
