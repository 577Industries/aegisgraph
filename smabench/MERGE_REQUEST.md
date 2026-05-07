# SMABench harness — merge request

Branch: `stream/smabench-harness` from `stream/integration`. Contains
the Phase 0 → real Ring 1 + Ring 2 transition outlined in SPEC §7
and `eng_plan.md` §11.5.

## Scope

This stream replaces the synthetic toy lists previously hardcoded in
`aegisgraph/smabench.py` with six parameterized, byte-deterministic
corpus generators. Ring 2 now consumes the real `extraction/output/`
graphs (with graceful degradation when the `real-extraction` stream
hasn't merged yet). Ring 3 stays as an authorization-only placeholder.

Owned files (modified):

- `aegisgraph/smabench.py` — full rewrite of the orchestrator.
- `smabench/__init__.py`, `smabench/ring1/__init__.py`,
  `smabench/ring2/__init__.py` — new packages.

Owned files (new):

- `smabench/ring1/_common.py` — shared `CorpusItem` + `write_corpus`
  helpers (deterministic JSON, file-write, manifest hash).
- `smabench/ring1/url_corpus.py` (real generator)
- `smabench/ring1/qr_corpus.py`
- `smabench/ring1/deeplink_corpus.py`
- `smabench/ring1/sync_corpus.py`
- `smabench/ring1/media_corpus.py`
- `smabench/ring1/pq_corpus.py`
- `smabench/ring1/<corpus-name>/generate.py` — six SPEC-mandated
  thin CLI shims that delegate to the underscore-named modules.
- `smabench/ring2/runner.py` — extraction-graph consumer.
- `tests/test_smabench_ring1_real_corpora.py` (12 tests)
- `tests/test_smabench_ring2_reads_real_extraction.py` (4 tests)
- `tests/test_smabench_repeatability.py` (4 tests)

No files were modified outside the agreed scope (no schema, no
`Makefile`, no other workstream subtree).

## Corpora summary

| Corpus | Items at default count | Determinism | Encoder |
|---|---|---|---|
| `url-corpus` | 10 000 | seed=42 byte-stable | grid + RNG fill |
| `qr-corpus` | 32 | seed=42 byte-stable | `qrcode` lib if present, else placeholder PNG with payload in tEXt chunk |
| `deeplink-corpus` | 1 000 | seed=42 byte-stable | grid (5 schemes × 5–10 sub-paths × 10 hosts × 8 injections × 5 fragments) |
| `sync-corpus` | 200 | seed=42 byte-stable | 8 Matrix + 7 Signal cases, JSON-serialized with `_synthetic_signal_envelope` flag (NO real protobuf) |
| `media-corpus` | 16 | seed=42 byte-stable | PIL solid-color 32×32 (PNG/JPEG/GIF/WEBP) — VALID samples only, NO crash inputs |
| `pq-corpus` | 60 | seed=42 byte-stable | 6 cases (PQXDH initial/rotation/migration + Megolm withheld/replayed/rotation) |

Each corpus emits per-item `<sha12>.<ext>` files plus a
`corpus.metadata.json` carrying:

- `name`, `item_count`, `requested_count`, `seed`
- `source_policy` ("synthetic")
- `publication_policy` ("sanitized_candidate")
- `generator` (module + axes)
- `items[]` with `(filename, sha256, category, size_bytes, extra)`
- `sha256` — SHA-256 of canonical JSON of the items array (byte-stable
  manifest hash; the property the repeatability check pins)

Filename prefix is 12 hex chars (the SPEC-documented `<sha8>` was
collision-prone at the 10 k URL grid; the helper retains the historical
backward-compat purge for 8-char prefixes from prior runs).

## Ring 2 wiring status

**Status:** `ring2_extraction_phase0` against the in-repo
`extraction/output/{signal,element-x}/graph.json` files committed to
`stream/integration`. The graphs ship 4 nodes / 1 record each, of
which 2 nodes carry "real-evidence" (the `target pin from v0.3 public
artifact package` anchor and the ReproChain pin) and 2 still carry
phase-0 markers. Aggregate score = 0.208.

When the `real-extraction` stream lands (extraction graphs with codeql /
semgrep / mobsf evidence), Ring 2 will automatically pick up the new
data and the status will flip to `ring2_real_evidence_present` without
any code change here. The ring2 runner's classification is:

- All graphs missing → `ring2_pending_extraction` (not a failure;
  the orchestrator keeps producing Ring 1 output).
- Some graphs missing → `ring2_partial_extraction`.
- All graphs phase-0 only → `ring2_extraction_phase0`.
- All graphs carry real evidence + ≥1 passing validation task →
  `ring2_real_evidence_present`.

`smabench/ring2/runner.py` opens extraction outputs read-only and
emits its own per-target summary into `results.json["rings"]["ring2"]`;
it never mutates extraction artifacts.

## Repeatability

Two consecutive end-to-end orchestrator runs produce byte-identical
output (modulo the `generated_at` timestamp). `repeatability.json`:

```json
{
  "byte_identical": true,
  "iterations": 2,
  "hash": "2bffc1fdb1f81d67186854eac1c8483b982a2fec4c47934ec0a6110092fc4c63",
  "secondary_hash": "2bffc1fdb1f81d67186854eac1c8483b982a2fec4c47934ec0a6110092fc4c63",
  "exclusions": ["generated_at"]
}
```

The hash excludes every `generated_at` field (top-level + any nested)
so calendar drift doesn't break repeatability. Tests
(`test_smabench_repeatability.py`) verify this via two consecutive
`smabench.run()` calls in a tmp_path.

## Top-3 recommendations (today)

The orchestrator emits zero recommendations against the current
extraction graphs because no Ring 2 target has score ≥0.7 — the
phase-0 anchor-only graphs cap the per-target score at 0.208. Once
the `real-extraction` stream raises evidence quality the gating
threshold will trip and recommendations will appear.

For demonstration, with the score gating set above 0.7 the orchestrator
would emit:

1. `AG-REC-SMABENCH-SIGNAL-MEDIA-001` — promote the Signal Android
   media-decode record from `validation_tasked` to `reviewed` by
   running `media-corpus` + `url-corpus` against the extraction graph.
2. `AG-REC-SMABENCH-ELEMENT_X-MEDIA-001` — same play for Element X
   Android.
3. (No third — only two targets in `aegisgraph.constants.TARGETS`.)

All recommendations validate against `schema/recommendation.schema.json`
(unit-tested in `test_smabench_repeatability.py`).

## Verification

```
$ make smabench
python3 -m aegisgraph.cli smabench run
smabench ring1 corpora: 6

$ python3 -c "
import json
r = json.load(open('smabench/results/latest/results.json'))
assert len(r['rings']['ring1']['corpora']) >= 6, r
assert r['repeatability']['byte_identical'], r
"
# (no output, exit 0)

$ pytest tests/test_smabench_*.py -q
....................                                                     [100%]
20 passed in 5.54s

$ python3 -m aegisgraph.cli validate
validation pass: 7 evidence records checked
```

## Constraints honored

- All corpora are explicitly synthetic. Every cryptographic field is
  a `synthetic_NOT_REAL_*`-prefixed placeholder; every UUID is
  `synthetic-`-prefixed; the Signal sync envelopes carry
  `_synthetic_signal_envelope: true` because we don't ship real Signal
  protobuf definitions.
- No live target probing. No credentialed interaction. No 0-day
  payloads. The media corpus is explicitly VALID samples only — its
  metadata flags `purpose: "harness-false-positive-baseline"` and
  the docstring documents the policy.
- Ring 3 stays `authorization_placeholder` with the "requires written
  authorization" policy text intact.
- No remote pushes performed.

## Out-of-scope (not done by this stream)

- The recommendation gating threshold (≥0.7) is opinionated; no
  attempt was made to tune it against the proposal evaluation rubric.
- The dashboard.html is intentionally a single-file static document;
  no live JS is loaded. Consumers needing a richer view should run
  the JSON islands through their own tooling.
- The orchestrator preserves the existing `STATIC_GENERATED_AT`
  timestamp (Phase 0 contract). When `real-extraction` lands and
  starts emitting fresh `generated_at` strings, the byte-identity
  check still holds because the exclusion list catches them.
