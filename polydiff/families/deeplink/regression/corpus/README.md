# PolyDiff deeplink-family regression corpus

This directory holds **hash-pin files only** for deeplink-family
anchored witnesses. Per Asemarefactor.md §"Engine 1: PolyDiff Extended"
and the schema additive-only policy (ADR-0010), witness BYTES never
appear in this repository.

## Layout

| File | What it pins |
|---|---|
| `anchor_android_intent_implicit_export.sha256` | An `intent://` URI that, when parsed by Android's Intent.parseUri, produces an Intent action that matches a non-declared filter in the SMA's manifest. The Android intent parser emits one action while the SMA's deeplink router resolves a different action from the same URI. Exercises the **intent_action divergence -> MEDIUM-HIGH** triage rule (Android intent-confusion / silent-export bug class). |
| `anchor_ios_universal_link_origin_confusion.sha256` | An HTTPS URL where NSURLComponents parses the authority one way and the SMA's link-handler parses it differently, producing origin-confusion. Exercises the **host divergence -> MEDIUM** triage rule (iOS universal-link origin-confusion class). |
| `anchor_deeplink_open_redirect.sha256` | A `signal://` URI with an embedded HTTP URL in a parameter. The proprietary-scheme parser surfaces the apex host with the embedded URL parked in `query_params`; a WHATWG-URL fallback resolves to the embedded host directly. If the SMA fetches the parameter without policy check, open-redirect surfaces. Exercises the **host + path divergence -> MEDIUM** triage rule and a documented deeplink open-redirect bug class. |
| `anchor_custom_scheme_traversal.sha256` | A custom-scheme URI (e.g. `sgnl://chat/../..//system/`) where the path component admits traversal. Custom-scheme parsers normalize traversal segments inconsistently. Exercises the **path divergence -> MEDIUM** triage rule (custom-scheme traversal / deeplink-traversal bug class). |

The canonical manifest with sizes, expected fact-vector diffs, and triage
expectations is `../corpus.json`. The rediscovery manifest with SHA pins
(Asemarefactor.md lines 35-37 contract) is `../INDEX.json`.

## Witness bytes provenance

The synthetic-bug witnesses are vendored privately at
`reprochain/corpora-private/dl_*.uri`. That directory is engineering-side
only and excluded from every public release through
`validator/sanitize_check.py` Rule 5 + the existing `EXCLUSIONS.md`
allowlist.

The deeplink family **never reads bytes** from the corpus in the
public/engineering pipeline. The diff engine operates on
`(witness_sha256, witness_size_bytes)` and per-implementation fact
vectors only.

## Public citation guidance

The Android Intent.parseUri implicit-export class is documented in
Android security guidance and public deeplink-security research. The
iOS universal-link origin-confusion class is documented in iOS
security guidance and academic surveys of universal-link
vulnerabilities. The deeplink open-redirect class is widely
documented in mobile-deeplink security research. The custom-scheme
traversal class is documented in URL-parsing-difference research
(Snyk-2022 URL-confusion class extended to proprietary schemes). All
four anchored cases here are synthetic representations of our own
design; specific public references for the historical bug variants
are retained engineering-private to avoid amplifying any still-
exploitable specifics.

## Network constraint

Deeplink-family wrappers MUST NOT fetch URLs over the network. The
URI witness bytes are supplied to each wrapper subprocess on stdin;
nothing in this directory or in the wrapper code is permitted to make
outbound HTTP requests. This invariant is checked by the wrapper
subprocess contract tests.
