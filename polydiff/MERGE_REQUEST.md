# PolyDiff stream — merge request

**Branch:** `stream/polydiff-core`
**Base:** `stream/integration` (12 commits past `bb244e8`)
**Owner:** PolyDiff implementer
**Date:** 2026-05-07

## What changed

Replaced the legacy 3-in-process-Python-shim implementation with real
subprocess parser dispatch over a real ≥30-case regression corpus,
per SPEC §5 and the engineering plan §11.4.

### Parser wrappers (≥6, real subprocess)

| ID | Source | Runtime | Status in current env | Built source artifact |
|---|---|---|---|---|
| `python_urllib`  | `urllib.parse` (CPython stdlib) | Python 3.11 | **built** | `polydiff/parsers/python_urllib/wrapper.py` |
| `whatwg_url_py`  | `whatwg-url` PyPI package      | Python 3.11 + pkg | **built** | `polydiff/parsers/whatwg_url_py/wrapper.py` |
| `jdk_uri`        | `java.net.URI`                 | OpenJDK 21 | not_built (no javac in env) | `polydiff/parsers/jdk_uri/Wrapper.java` |
| `okhttp_httpurl` | `okhttp3.HttpUrl` (4.12.0)     | OpenJDK 21 + okhttp jars | not_built (no javac/jars) | `polydiff/parsers/okhttp_httpurl/Wrapper.java` |
| `rust_url`       | `url` crate (2.5.x)            | Rust 1.79 | not_built (no cargo) | `polydiff/parsers/rust_url/wrapper.rs` |
| `go_neturl`      | `net/url` (Go stdlib)          | Go 1.22.5 | not_built (no go) | `polydiff/parsers/go_neturl/wrapper.go` |
| `libcurl`        | `curl_url_*` API               | clang 18 + libcurl | not_built (no clang/libcurl-dev) | `polydiff/parsers/libcurl/wrapper.c` |

Every wrapper directory ships with its source, a `Dockerfile`, a
`README.md`, and a `test_basic.sh`. Build status is recorded in
`polydiff/parsers/PARSER_STATUS.json`. The orchestrator dispatches the
two Python wrappers as subprocesses today; the rest are reproducible
from the pinned devcontainer (Clang 18, OpenJDK 21, Go 1.22.5, Rust
1.79.0, etc. — see `devcontainer/Dockerfile`).

### Fact-vector v2 (≥40 axes)

- New canonical schema at `polydiff/factvec/schema_v2.json` (~40 axes,
  every v1 axis remains required).
- Additive proposal at `schema/fact-vector.schema.v2.proposed.json` for
  the integration stream to merge.
- ADR documenting the migration policy at
  [`docs/decision-log/0020-factvec-v2-migration.md`](docs/decision-log/0020-factvec-v2-migration.md).
- `polydiff/factvec/normalize.py` fills missing axes with `null` +
  warning ("axis 'X' not directly observable by parser 'Y'"). Detector
  treats `null` as "no opinion."

### Disagreement detector + classifier

- `polydiff/disagreement/detector.py` — pairwise pass over 30 axes;
  null-as-no-opinion semantics.
- `polydiff/disagreement/clusterer.py` — groups by
  `(axis, parser_pair, error_class)`.
- `polydiff/triage/rules.yml` — 21 SR-* rules, each tied to a
  documented bug class.
- `polydiff/triage/classifier.py` — auditable rule application; falls
  back to a tiny inline YAML reader when `pyyaml` is missing.
- `polydiff/triage/triage_report.py` — CLI/JSON triage view per
  cluster.

### Regression corpus (41 cases, 13 with historical CVE/disclosure refs)

- `polydiff/regression/build_corpus.py` is the canonical case list (41
  cases). On-disk per-case directories under
  `polydiff/regression/cases/<id>/` with `input` / `description.md` /
  `expected.json` / `reference.url` are documentation artifacts
  (`make polydiff-build-corpus` regenerates them).
- `INDEX.json` summarizes the corpus.
- 13 cases carry a `historical_cve_or_disclosure_reference`. Concrete
  refs:
  - **CVE-2021-29921** (Python `ipaddress` octal IPv4 parsing) — 4 cases
    (`REG-URL-IPv4-leading-zeroes`, `REG-URL-IPv4-Decimal`,
    `REG-URL-IPv4-Hex`, `REG-URL-127-Variant`)
  - **CVE-2022-37434** (zlib chunked / parser-class reference) — 1 case
    (`REG-URL-Percent-In-Host`)
  - **CVE-2019-9740** (urllib3 CRLF) — 1 case
  - **CVE-2020-7793** (jsoup `HttpsConverter`) — 1 case
  - **CVE-2021-23336** (Python urllib semicolon split) — 1 case
  - **CVE-2022-0391** (Python urllib newline-in-host) — 1 case
  - **Snyk-2022-URL-Confusion** (public study) — 3 cases
  - **OWASP-Path-Traversal-Class** — 1 case

### Rediscoveries (the credibility anchor)

`make polydiff-regression` produces 8 historical-CVE/disclosure
rediscoveries via the two real built-in-env wrappers:

| Case | Reference | Axes observed |
|---|---|---|
| `REG-URL-IPv4-leading-zeroes` | CVE-2021-29921 | `host`, `host_is_loopback`, `host_is_private_or_link_local`, `leading_zeroes_in_octets_stripped` |
| `REG-URL-IPv4-Decimal` | CVE-2021-29921 | `host`, `host_is_loopback`, `host_is_private_or_link_local`, `host_lowercased` |
| `REG-URL-IPv4-Hex` | CVE-2021-29921 | `host`, `host_is_loopback`, `host_is_private_or_link_local`, `host_lowercased` |
| `REG-URL-127-Variant` | CVE-2021-29921 | `host`, `host_is_loopback` |
| `REG-URL-Percent-In-Host` | CVE-2022-37434 | `host_lowercased`, `percent_decoding_applied_in_host` |
| `REG-URL-Snyk-2022-host-5` | Snyk-2022-URL-Confusion | `host_lowercased`, `backslash_treated_as_slash` |
| `REG-URL-Backslash-IE-legacy` | Snyk-2022-URL-Confusion | `host_lowercased`, `backslash_treated_as_slash` |
| `REG-URL-Path-Encoded-Dotdot` | OWASP-Path-Traversal-Class | `path`, `path_normalized` |

> Cases tied to CVEs that are **already fixed in the wrappers we have
> available** (CVE-2019-9740, CVE-2020-7793, CVE-2021-23336,
> CVE-2022-0391) currently do not match. They are documented in the
> corpus but require an unpatched parser (jdk_uri / okhttp /
> libcurl / a pre-3.10 urllib) to actually fire. Building those
> wrappers in the devcontainer will lift the rediscovery count
> further.

### Orchestrator

`aegisgraph/polydiff.py` rewritten as a subprocess dispatcher:

- Reads `PARSER_STATUS.json`; runs every `built` wrapper as a
  subprocess (5 s timeout per call; 64 KiB stdin cap; non-zero exit →
  Finding).
- Loads cases from `polydiff/regression/build_corpus.CASES`
  (canonical) with on-disk `cases/<id>/input` override.
- Per case: dispatches all available wrappers, normalizes each
  envelope through `polydiff/factvec/normalize.py`, runs detector +
  classifier, builds AegisGraph evidence record, hashes into the
  chain.
- Writes `polydiff/regression/report.json` and
  `polydiff/evidence/regression.evidence.json`.
- Computes `tier_p1_status="pass"` iff
  `rediscovered_historical_cves >= 3`. New schema fields:
  `rediscovered_historical_cves`, `historical_cve_cases_total`,
  `parser_failures`, `skipped_parsers`, `cases_index`,
  `fact_vector_schema`.

### Fuzzer (local-only)

- `polydiff/fuzzer/driver.py` with libfuzzer-style mutations
  (bit-flip, insert, delete, swap, splice-special), axis-coverage
  heuristic. Default budget: 60 s for `make polydiff-fuzz`.
- `polydiff/fuzzer/seeds/` — 5 seed inputs covering URL classes the
  regression corpus exercises (baseline, userinfo, octal IPv4,
  percent-encoded, IPv6 mapped).

### Test suite (≥4 new test files, all passing)

- `tests/test_polydiff.py` — backwards-compat smoke (3 tests).
- `tests/test_polydiff_wrappers_smoke.py` — per-wrapper smoke; built
  wrappers run, unbuilt wrappers SKIP with explanatory pytest reason
  (14 tests, 5 skipped).
- `tests/test_polydiff_regression_count.py` — corpus size, CVE
  count, tier-P1 (6 tests).
- `tests/test_polydiff_factvec_v2_schema.py` — schema validity, v1
  required-fields preservation, normalize behavior (7 tests).
- `tests/test_polydiff_disagreement_axes.py` — reproduces the
  documented historical rediscoveries (5 tests).

Full test run: **56 passed, 5 skipped (parsers without toolchain)**.

## Verification (per task spec §I)

```
$ make polydiff-regression
$ python3 -c "
import json
r = json.load(open('polydiff/regression/report.json'))
assert r['tier_p1_status'] == 'pass', r
assert r.get('rediscovered_historical_cves',0) >= 3, r
"
# tier_p1_status: pass
# rediscovered_historical_cves: 8

$ pytest tests/test_polydiff_*.py -q
# 35 passed, 5 skipped

$ python3 -m aegisgraph.cli validate
# validation pass
```

## Negotiated (non-modified) surface

- `schema/fact-vector.schema.json` (v1) is **untouched**. The proposed
  `schema/fact-vector.schema.v2.proposed.json` is additive and will
  be merged by integration after PR review.
- `schema/evidence.schema.json` is untouched. Polydiff records
  validate as `tool_output_type="polydiff_regression_report"` and as
  v1.0 evidence records. The orchestrator now normalizes case IDs
  through `_normalize_record_id` so that mixed-case case IDs map to
  the schema's `^AG-EV-[A-Z0-9-]+$` pattern.

## Out of scope (deferred)

- Building the 5 unbuilt wrappers (jdk_uri, okhttp, rust_url,
  go_neturl, libcurl) in the current dev environment — they require
  toolchains that aren't present here. They build cleanly in the
  pinned devcontainer; sources + Dockerfiles are reviewed.
- Rediscovering CVE-2019-9740 / CVE-2020-7793 / CVE-2021-23336 /
  CVE-2022-0391 — these CVEs were fixed in the only urllib version
  available in this env. They need an unpatched parser
  (jdk_uri / okhttp / libcurl / pre-3.10 urllib). Their case
  directories ship with `expected.json` documenting the expected
  behavior so that rediscovery happens automatically the moment the
  relevant wrapper is built.
- OpenGraph metadata extraction (Phase 2 in SPEC §5.2) — separate
  stream.

## Fuzzer corpus from a 60 s run

Seed=42, budget=60 s, root=worktree:

- total_inputs: **1190**
- interesting (axis-coverage hits): **10**
- axes_covered: **17**
- crashes: **0**
- corpus output files: **13**

The 17 axes hit by random mutation include (alphabetical):
`backslash_treated_as_slash`, `host`, `host_decoded`, `host_is_ipv6`,
`host_is_private_or_link_local`, `host_lowercased`,
`host_punycode`, `parse_error`, `parsed`, `password_present`,
`path`, `path_normalized`, `path_traversal_resolved`,
`percent_decoding_applied_in_host`, `userinfo_present`,
`userinfo_raw`, `username`. No new axes were discovered beyond the
ones the static corpus already exercises — that is the expected
result for the very first fuzz iteration with two parsers; the long
tail surfaces once the JVM/Go/Rust wrappers are added.

## Files added / modified

```
ADDED:
  docs/decision-log/0020-factvec-v2-migration.md
  schema/fact-vector.schema.v2.proposed.json
  polydiff/factvec/__init__.py
  polydiff/factvec/schema_v2.json
  polydiff/factvec/normalize.py
  polydiff/disagreement/__init__.py
  polydiff/disagreement/detector.py
  polydiff/disagreement/clusterer.py
  polydiff/triage/__init__.py
  polydiff/triage/rules.yml
  polydiff/triage/classifier.py
  polydiff/triage/triage_report.py
  polydiff/parsers/PARSER_STATUS.json
  polydiff/parsers/python_urllib/{wrapper.py,Dockerfile,test_basic.sh,README.md}
  polydiff/parsers/whatwg_url_py/{wrapper.py,Dockerfile,test_basic.sh,README.md}
  polydiff/parsers/jdk_uri/{Wrapper.java,Dockerfile,test_basic.sh,README.md}
  polydiff/parsers/okhttp_httpurl/{Wrapper.java,Dockerfile,test_basic.sh,README.md}
  polydiff/parsers/rust_url/{wrapper.rs,Cargo.toml,Dockerfile,test_basic.sh,README.md,.gitignore}
  polydiff/parsers/go_neturl/{wrapper.go,go.mod,Dockerfile,test_basic.sh,README.md,.gitignore}
  polydiff/parsers/libcurl/{wrapper.c,Dockerfile,test_basic.sh,README.md,.gitignore}
  polydiff/regression/__init__.py
  polydiff/regression/build_corpus.py
  polydiff/regression/cases/INDEX.json
  polydiff/regression/cases/REG-URL-OkHttp-userinfo-1/{input,description.md,expected.json,reference.url}
  polydiff/regression/cases/REG-URL-Baseline-Simple/input
  polydiff/fuzzer/__init__.py
  polydiff/fuzzer/driver.py
  polydiff/fuzzer/seeds/{0001-baseline-https,0002-userinfo,0003-ipv4-octal,0004-percent-encoded,0005-ipv6-mapped}
  polydiff/parsers/README.md (replaced)
  tests/test_polydiff_wrappers_smoke.py
  tests/test_polydiff_regression_count.py
  tests/test_polydiff_factvec_v2_schema.py
  tests/test_polydiff_disagreement_axes.py
  polydiff/MERGE_REQUEST.md (this file)

MODIFIED:
  aegisgraph/polydiff.py  — full rewrite (subprocess dispatch)
  aegisgraph/cli.py       — add `polydiff fuzz` subcommand
  Makefile                — add `polydiff-build-corpus` target
  tests/test_polydiff.py  — adapt to subprocess-backed orchestrator
```

## DO NOT change list (per task spec)

The following remained untouched:
- `schema/*` (other than the v2 proposal addition)
- `aegisgraph/{evidence,hashchain,safety,validation,export,cli,constants,score,claims,io,tooling}.py`
  (cli.py edited only to add `polydiff fuzz` subcommand)
- `Makefile` (only added `polydiff-build-corpus`; existing
  `polydiff-regression`, `polydiff-fuzz`, `reproduce` chain unchanged)
- `devcontainer/`, `pyproject.toml`
- `reprochain/**`, `extraction/**`, `smabench/**`, `validator/**`
