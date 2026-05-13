# PolyDiff qr-family regression corpus

This directory holds **hash-pin files only** for qr-family anchored
witnesses. Per Asemarefactor.md §"Engine 1: PolyDiff Extended" and the
schema additive-only policy (ADR-0010), witness BYTES never appear in
this repository.

## Layout

| File | What it pins |
|---|---|
| `anchor_qr_apple_camera_url_handler.sha256` | A QR symbol encoding a URL where the iOS Camera URL handler extracts the URL differently than ZXing. Exercises the **detected_text divergence -> MEDIUM-HIGH** triage rule (URL-in-QR phishing surface). |
| `anchor_qr_structured_append_misorder.sha256` | A multi-QR structured-append sequence where two decoders disagree on the per-symbol index/total. Exercises the **structured_append_index / structured_append_total divergence -> MEDIUM** triage rule (multi-QR ordering bug class). |
| `anchor_qr_eci_unicode_confusion.sha256` | A QR symbol with an ECI header tagging UTF-8, but a decoder defaulting to Shift-JIS interprets the bytes differently. Exercises the **encoding_charset divergence -> MEDIUM** triage rule (charset-confusion class). |
| `anchor_qr_kanji_mode_ambiguity.sha256` | A QR symbol whose data fits both byte and kanji modes; two decoders disagree on which mode was used. Exercises the **mode divergence -> MEDIUM** triage rule (kanji-mode ambiguity class). |

The canonical manifest with sizes, expected fact-vector diffs, and triage
expectations is `../corpus.json`. The rediscovery manifest with SHA pins
(Asemarefactor.md lines 35-37 contract) is `../INDEX.json`.

## Witness bytes provenance

The synthetic-bug witnesses are vendored privately at
`reprochain/corpora-private/qr_*.png`. That directory is engineering-side
only and excluded from every public release through
`validator/sanitize_check.py` Rule 5 + the existing `EXCLUSIONS.md`
allowlist.

The qr family **never reads bytes** from the corpus in the
public/engineering pipeline. The diff engine operates on
`(witness_sha256, witness_size_bytes)` and per-implementation fact
vectors only.

## Public citation guidance

The URL-in-QR phishing class (iOS Camera URL handler vs ZXing
extraction divergence) is documented in mobile-QR security research.
The structured-append ordering bug class is documented in QR-decoder
research. The ECI vs default-charset interpretation difference is
documented in QR-decoder research and in the QR-Code specification's
ECI annex. The kanji-mode ambiguity class is documented in
QR-decoder research. All four anchored cases here are synthetic
representations of our own design; specific public references for the
historical bug variants are retained engineering-private to avoid
amplifying any still-exploitable specifics.

## Network constraint

QR-family wrappers MUST NOT fetch URLs over the network — even when
the decoded text is a URL. The image witness bytes are supplied to
each wrapper subprocess on stdin; nothing in this directory or in the
wrapper code is permitted to make outbound HTTP requests. This
invariant is checked by the wrapper subprocess contract tests.
