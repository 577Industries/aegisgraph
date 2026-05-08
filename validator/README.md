# AegisGraph Validator (`validator/`)

Hardened validator package — independent of `aegisgraph/`, owned by the validator-export stream. The contract is documented in **ADR 0021** (`docs/decision-log/0021-validator-hardening.md`); the human-gate posture it enforces is in **ADR 0011** (`docs/decision-log/0011-public-export-human-gate.md`).

The validator exists as a separate package so:

1. CI / external reviewers can run a non-mutating validation on a checkout without altering tracked files.
2. The sanitize gate (`validator/sanitize_check.py`) is the single source of truth for what is safe to leave the private repo. It is the only function authorized to return `True` from `aegisgraph.export._sanitize_check_passes`.
3. The traceability matrix (`validator/traceability_matrix.py`) hydrates the proposal claim-to-evidence map without depending on emitter internals — it reads SPEC.md headers, `docs/proposal-claims-index.yml`, `docs/dsip-requirements.yml`, and on-disk evidence files.

## CLI subcommands

The `validator.cli` dispatcher exposes four subcommands.

### 1. `validate` — schema + safety + hash-chain

```bash
python3 -m validator.cli validate
python3 -m validator.cli validate --non-mutating
```

By default this delegates to `aegisgraph validate` (which writes `validation-report.json`). With `--non-mutating`, returns the same report without writing to disk — used by CI / external reviewers who must not alter tracked files. Also gated by env var `AEGISGRAPH_VALIDATOR_NON_MUTATING=1`.

Expected output: `status="pass"`, all 6 schemas validated, all evidence records hash-chain verified.

### 2. `strict-tooling` — pinned-toolchain probe

```bash
python3 -m validator.cli strict-tooling --required clang,codeql,semgrep,docker,java,go,rustc
```

Probes the listed tools (e.g. `clang,codeql,semgrep,docker,java,go,rustc`). Exit 1 if any required tool is missing or below pin. Delegates to `aegisgraph.tooling` so this stream does not duplicate the pin table — the integration stream's `REQUIRED_TOOLS` table remains authoritative for `make reproduce`.

The caller passes a custom subset; the integration stream's `REQUIRED_TOOLS` table remains authoritative for `make reproduce`. Outside the pinned devcontainer this exits 1 (intentional fail-closed); see `tooling-versions.json` for the current host's tool inventory.

### 3. `sanitize-check` — public-export gate

```bash
python3 -m validator.cli sanitize-check exports/public-sanitized/
```

Scans a public-sanitized export tree for forbidden patterns, misclassified safety-posture, embedded crash bytes, and overclaim promotion. Used by `aegisgraph/export.py` via lazy import (`is_export_safe`) and by `.github/workflows/sanitize.yml` as the fail-closed gate.

The check enforces **12 substantive rules + 6 structural rules** (see `validator/sanitize_check.py`):

- **Substantive (12)**: forbidden FS-path / credential / private-key strings; finding-state coherence; novel-private-candidate exclusion; tool-output safety-posture; embedded crash-byte rejection (via `aegisgraph.safety.BLOCKING_PATTERNS`); static-only-claim overclaim guard; standards-mapping caveat presence; disclosure-status whitelist; manifest schema conformance; release_authorized flag; raw-bytes rejection; private-path rejection.
- **Structural (6)**: tree depth, file-count bounds, no-symlink follow, file-extension allowlist, manifest presence, hash-chain integrity.

Exit 0 on no failures; exit 1 with one failure per line on any violation. The CLI is fail-closed: import errors, scan exceptions, or missing `aegisgraph.safety` all return False / exit 1.

### 4. `traceability` — claim → evidence matrix

```bash
python3 -m validator.cli traceability
```

Emits `reports/traceability_matrix.{json,md}` from:

- SPEC.md section headers (claim source)
- `docs/proposal-claims-index.yml` (proposal-side claim catalog)
- `docs/dsip-requirements.yml` (DSIP requirement catalog)
- on-disk evidence files (per-stream emitter outputs)

Output format: a JSON document keyed by `claim_id` with an `evidence_refs[]` list (each entry: `path`, `field`, `tool_used`, `status`) plus an `unanchored_claims` array for claims that the matrix could not match against any on-disk evidence. The `.md` rendering is human-readable for proposal review.

A non-zero `claim_without_evidence` count is **expected and documented** (Phase 0 / Phase 1 anchoring is incomplete by design); reviewers should not block on it.

## Expected output

```
$ python3 -m validator.cli validate
[validate] schemas=6 valid; records=N validated; hash-chain=ok
status: pass

$ python3 -m validator.cli traceability
[traceability] sources: SPEC.md (K headers), proposal-claims-index.yml (M),
               dsip-requirements.yml (D), evidence files (E)
[traceability] anchored=A unanchored=U
wrote reports/traceability_matrix.json
wrote reports/traceability_matrix.md

$ python3 -m validator.cli sanitize-check exports/public-sanitized/
status: ok (no failures)
```

## Why a separate `validator/` package?

Documented in ADR 0021. Short version: the validator must be importable from CI without dragging in `aegisgraph/` runtime state, so that an external auditor can run `python3 -m validator.cli sanitize-check <tarball>` against a candidate release without first installing the full AegisGraph emitter chain. The hardening also lets us fail-closed when `aegisgraph.safety` is absent or broken — the validator never silently treats an export as safe.

## Tests

Validator-side tests live under `tests/`:

- `test_validator_non_mutating.py` — `validate --non-mutating` does not write `validation-report.json`
- `test_validator_sanitize_check.py` — sanitize-check fixtures (clean + 5 poisoned)
- `test_validator_strict_tooling.py` — strict-tooling probe behavior
- `test_sanitize_check.py` — direct `validator.sanitize_check` API
- `test_strict_tooling.py` — direct `validator.cli strict-tooling` invocation
- `test_traceability.py`, `test_traceability_matrix.py` — matrix emission and shape

Run `python3 -m pytest tests/test_validator_*.py tests/test_sanitize_check.py tests/test_traceability*.py tests/test_strict_tooling.py -q` to exercise this package end-to-end.
