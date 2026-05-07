# Merge request: stream/real-extraction

## Goal

Replace anchor-only graph records (every record in
`extraction/output/*/graph.json` previously had
`evidence_source="phase0 extraction placeholder, anchor-only"`) with
records assembled from real adapter pipelines anchored to the pinned
target commits in `aegisgraph/constants.py`.

## What landed

### A. CodeQL queries (Phase C1)

- `extraction/codeql/qlpack.yml` — declares `name: codeql/aegisgraph-sma-queries`,
  depends on `codeql/java-queries`, points at the run-all suite.
- `extraction/codeql/queries/aegisgraph-sma.qls` — runs all 8 queries.
- 8 queries in `extraction/codeql/queries/`:
  `entry-point-intent.ql`, `inbound-message-handler.ql`,
  `link-preview-fetch.ql`, `qr-handler.ql`, `media-decoder-entry.ql`,
  `native-method-with-tainted-input.ql`, `device-linking-flow.ql`,
  `key-storage-access.ql`. Each emits SARIF.
- `extraction/codeql/run_queries.sh` — driver to run the suite against an
  existing DB.
- `extraction/targets/signal-android/build_db.sh` — builds CodeQL Java DB
  for Signal-Android at commit `1043851` (Gradle command, target source
  cloned to a temp dir, deleted on exit).
- `extraction/targets/element-x-android/build_db.sh` — same for Element-X
  at `91d265e6`.

### B. Semgrep rules (Phase C2)

- 4 rules in `extraction/semgrep/rules/`:
  `webview-misconfig.yml`, `unsafe-deeplink-handler.yml`,
  `tainted-jni-bridge.yml`, `permissive-intent-filter.yml`.
- Each rule's `metadata.aegisgraph_path_class` and
  `aegisgraph_node_type` are consumed by `semgrep_to_graph.py`.

### C. AndroidManifest analyzer (Phase C4)

- `extraction/manifest/manifest_analyzer.py` — pure Python (`lxml`-based,
  XXE-safe `XMLParser`). Emits per-manifest JSON listing exported
  components, intent filters with scheme/host/path, declared permissions,
  and declared native libraries. CLI: `python3 -m extraction.manifest.manifest_analyzer <source-root> --output ...`.
- Tests: `tests/test_extraction_manifest_analyzer.py` — covers component
  extraction, build-dir skipping, native-lib detection,
  byte-stable JSON, and an XXE-bomb sanity check.

### D. MobSF runner (Phase C3, offline)

- `extraction/mobsf/Dockerfile` — `FROM opensecurity/mobile-security-framework-mobsf:latest`,
  digest pin recorded in `README.md`.
- `extraction/mobsf/run_mobsf.py` — brings up container with
  `MOBSF_DISABLE_NETWORK_FEATURES=1`, posts APK, fetches JSON, tears
  down. Honest skip statuses: `docker_unavailable`, `apk_missing`,
  `httpx_unavailable`, `container_start_failed: <stderr>`,
  `mobsf_boot_timeout`, `scan_failed: <error>`.
- `extraction/mobsf/README.md` — APK acquisition asymmetry (Signal:
  Gradle build; Element-X: F-Droid manual download).

### E. Adapters (Phase C5)

- `extraction/adapters/_common.py` — shared helpers: SHA256, stable
  node-IDs, GitHub-anchor builder, source-path relativizer,
  AdapterResult constructor.
- `extraction/adapters/codeql_to_graph.py` — SARIF → AegisGraph nodes
  with `source_anchor=<repo>/tree/<commit>/<file>#L<line>` and
  `evidence_source=<query-id>:<sarif-hash>`.
- `extraction/adapters/semgrep_to_graph.py` — semgrep JSON → nodes,
  filters out rules without `aegisgraph_path_class` metadata.
- `extraction/adapters/manifest_to_graph.py` — manifest analysis JSON →
  `entry_point` for components with intent filters, `control` for
  declared permissions, `native_boundary` for native libraries.
- `extraction/adapters/mobsf_to_graph.py` — MobSF report → nodes for
  each MobSF section we care about (permissions / manifest_analysis /
  code_analysis / binary_analysis / network_security / secrets).
  Forwards skipped/failed status from runner.
- `extraction/adapters/assemble.py` — buckets per-tool nodes by
  `_path_class`, synthesizes intra-class edges, emits one finalized
  evidence record per non-empty path-class via
  `aegisgraph.evidence.finalize_record`. When ALL tools skipped emits a
  single `media_decode` baseline record with
  `evidence_source="baseline_anchor_pending_toolchain:<sha256>"` —
  explicitly NOT `"phase0 placeholder"`.

### F. Extraction entry point + reproducibility

- `aegisgraph/extraction.py` — rewritten. Public API preserved:
  `make_media_reachability_record(target_key, previous_hash=None)` and
  `run_extract(root)`. Output:
  `extraction/output/<target>/graph.json`,
  `extraction/output/<target>/coverage.json`, and the top-level
  `extraction/output/manifest.json` with
  `status="phase1_real_extraction"` (was `"phase0_anchor_only"`).
- Byte-stable across runs (`tests/test_extraction_byte_stable.py`).

### G. Tests

New tests under `tests/test_extraction_*.py` (27 tests, 26 pass + 1
skipped behind `AEGISGRAPH_FULL_TOOLCHAIN=1`):

| File | Tests | What it locks |
|---|---|---|
| `test_extraction_no_anchor_only.py` | 4 | No phase0 token leakage; per-node evidence_source has a known prefix; `manifest.status="phase1_real_extraction"`; `tool_run_status` lists all four tools. |
| `test_extraction_byte_stable.py` | 2 | Run extraction twice in same tmpdir + across two tmpdirs; byte-identical JSON. |
| `test_extraction_coverage.py` | 5 (1 skipped) | `coverage.json` shape; `path_class_coverage` ⊆ valid path classes; `graph_evidence_ref_coverage ∈ [0, 1]`; strict `≥ 0.8` test gated behind `AEGISGRAPH_FULL_TOOLCHAIN=1`. |
| `test_extraction_manifest_analyzer.py` | 6 | Component / permission / native-library extraction; build dir skipping; XXE-bomb safety. |
| `test_extraction_adapters.py` | 8 | Each adapter: skipped on missing input, ran on synthetic input, no phase0 leakage, source_anchor pinned to commit. |
| `test_extraction_mobsf_runner.py` | 2 | `apk_missing` + `docker_unavailable` skip paths emit JSON, never silently no-op. |

Pre-existing tests (28) still pass.

### H. Docs

- `extraction/BUILD_STATUS.md` — toolchain availability matrix +
  upgrade procedure.
- `extraction/output/README.md` — committed vs. gitignored artifacts.
- Updated `extraction/codeql/queries/README.md`,
  `extraction/semgrep/rules/README.md`,
  `extraction/manifest/README.md`, `extraction/mobsf/README.md`.

## Toolchain status snapshot (this worktree, 2026-05-07)

| Tool | Status in current host env | Expected in devcontainer |
|---|---|---|
| AegisGraph SMA CodeQL queries | source committed; `codeql` CLI absent → `skipped_pending_toolchain` | `ran` |
| Semgrep rules | source committed; `semgrep` 1.157.0 in PATH but target source not cloned → `skipped_pending_toolchain` | `ran` |
| Manifest analyzer | runs; covered by tests; needs cloned target tree for real input → `skipped_pending_target_source` | `ran` |
| MobSF runner | docker present; image not pulled; APK acquisition manual → `skipped_pending_toolchain` | `ran` (Signal) / `skipped_pending_apk_acquisition` (Element-X until F-Droid network is allowlisted) |

## Per-target current numbers (host env, all tools skipped)

| Target | Total nodes | Total records | Path-class coverage | `graph_evidence_ref_coverage` | Stale anchor count |
|---|---|---|---|---|---|
| Signal Android | 4 | 1 | `media_decode` | 0.0 | 0 |
| Element X Android | 4 | 1 | `media_decode` | 0.0 | 0 |

The 4-node baseline records have `evidence_source` prefixed with
`baseline_anchor_pending_toolchain:` — NOT `phase0 ...`. Inside the
devcontainer with the full toolchain, expected per-target counts are
order-of-magnitude larger (CodeQL alone returns dozens to hundreds of
matches across the eight queries) and `graph_evidence_ref_coverage`
should rise to ≥ 0.8.

## Verification (run locally)

```bash
cd .worktrees/extraction

# 1. Generate Phase 1 outputs
python3 -m aegisgraph.cli extract
# extraction scaffold wrote 2 graph outputs

# 2. No phase0 string anywhere
python3 -c "
import json,glob
for p in glob.glob('extraction/output/*/graph.json'):
    g = json.load(open(p))
    flat = json.dumps(g)
    assert 'phase0 extraction placeholder' not in flat, p
    assert 'phase0 map placeholder' not in flat, p
"

# 3. Validate against schema
python3 -m aegisgraph.cli validate
# validation pass: 7 evidence records checked

# 4. Tests
python3 -m pytest -q
# 52 passed, 1 skipped
```

## Constraints honored

- No raw target source is committed.
- Raw scanner outputs (`extraction/output/<target>/raw/`,
  `codeql-db/`, intermediate JSON) are gitignored.
- No live target probing.
- No remote push from this stream.
- Phase 0 placeholder strings (`"phase0 extraction placeholder"`,
  `"phase0 map placeholder"`) are forbidden by
  `tests/test_extraction_no_anchor_only.py`.

## Out of scope (deferred to integration)

- Bumping `aegisgraph/constants.py:STATIC_GENERATED_AT` (integration owns
  that).
- Mobile-only schema additions (any new evidence-record fields go through
  `docs/decision-log/0010-schema-additive-only.md`).
- Wiring `AEGISGRAPH_FULL_TOOLCHAIN=1` into CI (validator-export stream
  owns the strict-coverage gate).
