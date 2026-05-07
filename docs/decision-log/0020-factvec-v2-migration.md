# 0020 — Fact Vector v2 migration (additive, non-breaking)

**Status:** Proposed
**Owner:** PolyDiff stream (`stream/polydiff-core`)
**Reviewers:** Integration stream (owns `schema/`), Validator stream (owns evidence-validation flow)
**Date:** 2026-05-07

## Context

The current canonical schema for PolyDiff URL fact vectors is
[`schema/fact-vector.schema.json`](../../schema/fact-vector.schema.json) (v1). It encodes
9 axes:

```
input_id, parser_profile, scheme, host, port, path, userinfo_present,
host_is_private_or_link_local, parse_error
```

This was sufficient for the first round of regression scaffolding —
which used three in-process Python wrappers and four synthetic cases
to drive a smoke check that the disagreement detector worked at
all — but it is **insufficient** for the work described in
[`SPEC.md`](../../SPEC.md) §5.4, which calls for ~40 axes derived from
the public corpus of historical URL-parser bug reports.

Concretely, v1 cannot represent:

- `parsed` (whether the parser accepted the input as a URL at all). v1
  collapses this into `parse_error`, which is too coarse.
- Per-parser `errors[]` / `warnings[]` arrays (parsers emit multiple
  diagnostics; v1 accepts a single string).
- Sub-axes the SR-* security-relevance rules in SPEC §5.6 directly
  reference, e.g. `host_lowercased`, `host_is_loopback`,
  `host_is_ipv4`, `host_punycode`, `host_has_idn`,
  `path_traversal_resolved`, `percent_decoding_applied_in_host`,
  `backslash_treated_as_slash`, `tab_or_newline_stripped`,
  `control_chars_in_host_rejected`,
  `scheme_authority_separator_strict`.

Without those axes, the security-relevance classifier is forced to
re-derive them from the small v1 surface, which both duplicates parser
behavior in the orchestrator (defeating the point of differential
testing) and fails to distinguish real parser disagreement from
orchestrator post-processing.

## Decision

Adopt a v2 fact-vector schema as an **additive** successor to v1.

- Every v1-required field remains v2-required (backwards-compatible).
- v2 adds ~30 axes (see schema for the full list). All new axes are
  nullable (`type: ["X", "null"]`).
- v2 adds three required fields not in v1:
  - `parsed: boolean` — separates "parser accepted the bytes" from
    "parser produced an error string." A wrapper that returns
    `parsed=false` MUST also populate `errors[]`.
  - `errors: string[]` — diagnostics emitted by the parser.
  - `warnings: string[]` — orchestrator-side notes, including
    "axis X not directly observable" entries from
    `polydiff/factvec/normalize.py` for axes the parser cannot expose.
- v2 keeps `parse_error` for backwards compatibility. Wrappers SHOULD
  set it to `null` and use `errors[]`; the v1 `parse_error` field is
  retained so legacy v1-only consumers continue to work.
- Detector treats any `null` axis value as **"no opinion"** and
  excludes it from disagreement comparisons. This prevents false
  positives where parser A reports an axis and parser B does not
  expose it.

## Migration policy

1. **No mutation of v1.** `schema/fact-vector.schema.json` is not
   touched by this stream. The proposal lives at
   `schema/fact-vector.schema.v2.proposed.json` until integration
   reviews and merges it.
2. **Bridge module.** `polydiff/factvec/normalize.py` reads
   parser-native output and emits the canonical v2 envelope. Each
   wrapper emits as much of v2 as it can express; `normalize.py`
   fills gaps with `null` + a warning string of the form
   `"axis 'X' not directly observable by parser 'Y'"`.
3. **Fact-vector emitted by `aegisgraph/polydiff.py`** carries
   `schema_version: "v2"`. The existing v1 schema is left in place;
   evidence records that referenced v1 (the legacy regression report
   and the smoke test record) are not retroactively re-keyed — they
   remain valid v0.3 evidence.
4. **Evidence schema unchanged.** `schema/evidence.schema.json` already
   accepts `tool_output_type: "polydiff_regression_report"`. This is
   not an evidence-schema migration; it is a tool-output internal
   schema migration. Integration retains full ownership of the
   evidence schema.

## Consequences

- The detector becomes simpler (one axis comparison loop) and gains
  fidelity (fewer false-positive disagreements driven by orchestrator
  post-processing).
- The triage classifier can name SR-* rules directly against axes
  rather than recomputing them.
- Parsers that lack a feature (e.g. urllib does not natively expose
  IDN-vs-punycode flags) get an honest `null` in those axes rather
  than an orchestrator-fabricated value. Disagreement reports become
  more accurate.
- Public consumers reading existing v0.3 evidence records continue to
  validate against the v1 schema. There is no break.

## Open questions

- Whether the integration stream wants the v2 file moved to
  `schema/fact-vector.schema.v2.json` (drop the `proposed` suffix) at
  merge time. The proposal does not assume that filename.
- Whether the validator (`aegisgraph/validation.py`) should accept
  both v1 and v2 fact vectors going forward. Default
  recommendation: yes, with a v1 deprecation note in the validator
  output once integration ratifies v2.
