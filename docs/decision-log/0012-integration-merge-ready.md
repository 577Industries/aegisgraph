# 0012 Integration stream merge-ready

Status: integration-ready (first-cut). Reviewed before any downstream
stream rebases onto `stream/integration`.

## Author

Integration stream, single-session land. All commits unpushed.

## Branch and base

- Branch:           `stream/integration`
- Base:             `bb244e8` ("Initial Tier 3 research scaffold")
- Tip:              (top of `git log --oneline` on `stream/integration`)
- Pushed:           NO. Per the integration stream prompt, `git push` is
                    forbidden in this stream. The reviewer (user) pushes
                    after review.

## What is in this branch (12 commits)

| # | Subject |
|---|---|
| 01 | chore: gitignore .worktrees/ for parallel-stream isolation |
| 02 | feat(devcontainer): pin Clang 18, OpenJDK 21, CodeQL 2.20.6, Android NDK r26d, Go 1.22.5, Rust 1.79.0, Node 20 |
| 03 | feat(tooling): add REQUIRED_TOOLS table and --strict gate |
| 04 | feat(make): add tooling-strict, traceability, sanitize-check, *-fuzz targets |
| 05 | feat(schema): assert all 6 schemas are valid Draft 2020-12 + add additive-only ADR |
| 06 | feat(safety): finalize_record raises on blocking flags for public-classified records |
| 07 | feat(export): public-sanitized release_authorized fail-closed + --dry-run |
| 08 | docs(integration): add operating-procedures.md |
| 09 | ci: add reproduce + sanitize workflows; update ci.yml for stream branches |
| 10 | feat(traceability): scaffold proposal-claims-index, dsip-requirements, /reports/ contract |
| 11 | docs(adr): add 0007 libwebp-over-forcedentry, 0008 polydiff-over-mls, 0009 libwebp-pins template, 0011 public-export-human-gate |

## Deliverables map (from the integration prompt)

| Prompt deliverable | Commit | Status |
|---|---|---|
| 1. gitignore .worktrees/ | 01 | Done |
| 2. Pin tooling in devcontainer | 02 | Done |
| 3. Strict tooling mode | 03 | Done |
| 4. New Make targets | 04 | Done |
| 5. Schema management (validate Draft 2020-12, additive-only ADR) | 05 | Done |
| 6. evidence.finalize_record() safety scan | 06 | Done |
| 7. Public-sanitized export contract (fail-closed + --dry-run) | 07 | Done |
| 8. Operating procedures doc | 08 | Done |
| 9. CI workflows (ci.yml + reproduce.yml + sanitize.yml) | 09 | Done |
| 10. Traceability scaffolding | 10 | Done |
| 11. ADRs (libwebp/polydiff/pins/additive/human-gate) | 05 + 11 | Done |
| 12. Quality gates run | (this doc) | Documented below |

## Schema deltas accepted

None. The integration stream is the FIRST stream to land; no downstream
schema deltas have arrived. The additive-only policy is now codified in
`docs/decision-log/0010-schema-additive-only.md` and enforced by
`tests/test_schema_validation.py`.

## Merge order applied

The merge order documented in `docs/operating-procedures.md` section 4
is:
  smabench-harness → polydiff-core → reprochain-proof → real-extraction → validator-export

No downstream stream merges have happened on this branch yet. Once the
reviewer pushes `stream/integration`, the smabench-harness stream is the
first to rebase + open a PR back to integration.

## Quality gates run on this branch tip

```
cd .worktrees/integration

git status                     -> clean
python -m pytest -q            -> 28 passed (was 11 at base)
python -m aegisgraph.cli validate
                               -> "validation pass: 7 evidence records checked"
make tooling-strict            -> exit 1 (FAIL — expected on this dev box)
                                  Missing on this host: clang, codeql,
                                                        docker, go, rustc
                                  Available on this host: git, java
                                  (21.0.10), make, node (v22.22.0),
                                  python (3.12.3), semgrep (1.157.0)
make reproduce                 -> halts at tooling-strict step (intended).
                                  Skipping that step manually:
                                    make extract                  -> 2 graphs written
                                    make reprochain-build         -> blocked_pending_commit_pin (intended)
                                    make reprochain-run           -> not_run_until_commit_pins_confirmed (intended)
                                    make reprochain-map           -> 2 mapped
                                    make polydiff-regression      -> 3 records, pass
                                    make smabench                 -> 5 ring1 corpora
                                    make validate                 -> 7 records, pass
                                    make export-private           -> 11 artifacts, validation=pass
make sanitize-check            -> not run (validator-export stream owns
                                  validator/sanitize_check.py; the
                                  GitHub Actions workflow exits 0 if
                                  exports/public-sanitized/ does not
                                  exist).
```

Note: `make reproduce` correctly fails-closed at `make tooling-strict` on
this dev box because Clang 18, CodeQL CLI, Docker, Go, and Rust are not
installed. This is the INTENDED behavior. The pinned devcontainer at
`devcontainer/Dockerfile` provides all of them; once the devcontainer is
built (or once a self-hosted runner with the pinned toolchain is wired
to `.github/workflows/reproduce.yml`), `make reproduce` succeeds end-to-end.

## Test growth

| Layer | Tests at base (bb244e8) | Tests now |
|---|---|---|
| `tests/test_claims.py` | 2 | 2 (unchanged) |
| `tests/test_hashchain.py` | 1 | 1 (unchanged) |
| `tests/test_polydiff.py` | 2 | 2 (unchanged) |
| `tests/test_safety.py` | 3 | 3 (unchanged) |
| `tests/test_smabench.py` | 1 | 1 (unchanged) |
| `tests/test_validation_e2e.py` | 1 | 1 (unchanged) |
| `tests/test_schema_validation.py` | 1 | **8** (+ Draft202012Validator parametrize, baseline-presence) |
| `tests/test_e2e_reproduce.py` | 0 | **4** (NEW) |
| `tests/test_export_private_complete.py` | 0 | **6** (NEW) |
| **Total** | **11** | **28** |

## Blockers and decisions for the user

1. **Push the branch.** The integration stream prompt forbids `git push`
   from this branch. The user pushes `stream/integration` so downstream
   streams can rebase.

2. **Self-hosted runner for `make reproduce`.** `.github/workflows/reproduce.yml`
   is gated `if: false` until a self-hosted runner with the pinned
   devcontainer image is provisioned. Until then the integration owner
   runs `make reproduce` on a maintainer workstation. No code change
   needed; flip the `if: false` to `if: ${{ vars.SELF_HOSTED_AVAILABLE }}` (or similar)
   when the runner exists.

3. **Existing ADRs 0001–0006.** The Phase 0 scaffold shipped six ADRs
   covering different decisions than the integration prompt requested.
   I preserved them and added the prompt-requested ADRs as 0007–0011.
   This means `0003-libwebp-selection.md` (Phase 0) and
   `0007-libwebp-over-forcedentry.md` (this stream) coexist; their content
   does not conflict but the user may want to consolidate them. I did
   not consolidate because that would have rewritten history this branch
   does not own. Decision is the user's.

4. **`_sanitize_check_passes` stub.** `aegisgraph/export.py` has a stub
   that returns False. The validator-export stream replaces it with
   `validator.sanitize_check.scan_public_export(...).ok` when its module
   lands. Until then `release_authorized` is structurally False — see
   `docs/decision-log/0011-public-export-human-gate.md`. This is the
   correct fail-closed posture; no action required.

5. **MobSF docker image digest.** `devcontainer/Dockerfile` documents
   that `opensecurity/mobile-security-framework-mobsf:latest` is pulled
   at runtime by `make extract-deep`. The actual digest pin is owned by
   `extraction/mobsf/README.md`, which the validator-export stream
   updates. Today the README contains policy text but not a digest.
   Not a blocker for merge of `stream/integration`, but the
   real-extraction stream should add the digest as part of its merge.

6. **Existing `tests/test_validation_e2e.py` and the new `tests/test_e2e_reproduce.py`** overlap by design. The integration stream's new test
   file owns the e2e contract for THIS stream; the legacy test stays as
   a Phase 0 fixture. Either is sufficient; deleting the legacy is the
   user's call.

## Files added or modified by this branch

```
A  .github/workflows/reproduce.yml
A  .github/workflows/sanitize.yml
M  .github/workflows/ci.yml
M  .gitignore
A  Makefile                                  (rewritten, all old targets preserved)
M  aegisgraph/cli.py
M  aegisgraph/evidence.py
M  aegisgraph/export.py
M  aegisgraph/tooling.py
A  devcontainer/Dockerfile
M  devcontainer/devcontainer.json
A  devcontainer/post-create.sh
A  docs/decision-log/0007-libwebp-over-forcedentry.md
A  docs/decision-log/0008-polydiff-over-mls.md
A  docs/decision-log/0009-libwebp-cve-2023-4863-pins.md
A  docs/decision-log/0010-schema-additive-only.md
A  docs/decision-log/0011-public-export-human-gate.md
A  docs/decision-log/0012-integration-merge-ready.md   (this file)
A  docs/dsip-requirements.yml
A  docs/operating-procedures.md
A  docs/proposal-claims-index.yml
M  pyproject.toml
A  reports/README.md
M  tests/test_schema_validation.py
A  tests/test_e2e_reproduce.py
A  tests/test_export_private_complete.py
```

Files NOT touched (other streams own them):
- `reprochain/**`
- `extraction/**`
- `polydiff/**`
- `smabench/**`
- `validator/**`
- existing ADRs `0001-0006`
- existing schemas `schema/*.schema.json` (no contents changed; the only
  schema-related change is the `tests/test_schema_validation.py`
  expansion that asserts they are well-formed)

## Verification commands the reviewer can re-run

```bash
cd "/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/01_TIER3_RESEARCH/AegisGraph_Tier3_Research/.worktrees/integration"
git status            # clean
git log --oneline     # 12 commits since bb244e8
python3 -m pytest -q  # 28 passed
python3 -m aegisgraph.cli validate    # status="pass"
python3 -m aegisgraph.cli tooling     # writes tooling-versions.json
python3 -m aegisgraph.cli tooling --strict  # exits 1 outside the devcontainer
python3 -m aegisgraph.cli export public-sanitized --dry-run
                      # release_authorized=False, dry_run=true, no files written
```

## Related

- 0010 — schema additive-only (this branch codifies the policy)
- 0011 — public-export human gate (this branch wires the fail-closed gate)
- 0021 — validator hardening (the follower stream that lands `validator/sanitize_check.py` and replaces the stub)

## Proposal claims

- (process) — this ADR is process / branch-state and does not directly substantiate a CETM claim, but it is the integration handoff that lets ReproChain + PolyDiff + Extraction evidence reach the public-export sanitize boundary.
