# PolyDiff image-family regression corpus

This directory holds **hash-pin files only** for image-family anchored
witnesses. Per Asemarefactor.md §"Engine 1: PolyDiff Extended" and the
schema additive-only policy (ADR-0010), witness BYTES never appear in
this repository.

## Layout

| File | What it pins |
|---|---|
| `anchor_CVE-2023-4863.webp.sha256` | Heap buffer overflow in libwebp's `BuildHuffmanTable` (VP8L Huffman table). Reachable in Signal Android via Glide -> libwebp fallback. Fixed in libwebp v1.3.2. Used as the ground-truth case proving the methodology. |
| `anchor_synthetic_oversize_dim.webp.sha256` | Synthetic anchor exercising the **dimensions divergence -> MEDIUM** triage rule (Asemarefactor.md line 90). |
| `anchor_synthetic_animated_frame_count.webp.sha256` | Synthetic anchor exercising the **frame_count divergence -> MEDIUM-HIGH** triage rule (line 92, libwebp animated WebP class). |
| `anchor_synthetic_color_profile_divergence.webp.sha256` | Synthetic anchor exercising the **color_space divergence with same pixels -> LOW** noise channel (line 89). |

The canonical manifest with sizes, expected fact-vector diffs, and triage
expectations is `../corpus.json`. The rediscovery manifest with SHA pins
(Asemarefactor.md lines 35-37 contract) is `../INDEX.json`.

## Witness bytes provenance

The CVE-2023-4863 witness is vendored privately at
`reprochain/corpora-private/CVE-2023-4863.webp`. That directory is
engineering-side only and excluded from every public release through
`validator/sanitize_check.py` Rule 5 + the existing `EXCLUSIONS.md`
allowlist.

The image family **never reads bytes** from the corpus. The diff engine
operates on `(witness_sha256, witness_size_bytes)` and per-implementation
fact vectors only.
