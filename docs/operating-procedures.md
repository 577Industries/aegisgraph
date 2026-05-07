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
