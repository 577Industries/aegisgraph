# Handcrafted private corpus

This directory holds the seed inputs that `reprochain/build.sh` and
`make reprochain-run` feed into the libFuzzer + ASan harness.

## Rules

1. The `*.webp`, `*.bin`, and any other input files in this directory
   are **gitignored** (`.gitignore` excludes everything except this
   `README.md` and `MANIFEST.json`). They are never committed to git
   history. The CVE-2023-4863 PoC is publicly cited in research
   writeups but the AegisGraph repo intentionally does not redistribute
   crash-triggering bytes.
2. The committed `MANIFEST.json` lists each input by sha256 + a
   structural one-liner ("VP8L lossless, intentionally-malformed
   Huffman code-length stream") with no payload bytes and no exact
   byte offsets.
3. New inputs are added by writing the file into this directory, then
   running:
       python3 -m aegisgraph.cli reprochain build  # idempotent; refreshes manifest hashes
   or, equivalently, the harness can be invoked directly:
       fuzz_webp_decode_vuln reprochain/corpora-private/handcrafted/
4. Anything resembling captured production traffic, undisclosed
   crash payloads, or weaponization material does NOT go here. This is
   a research seed corpus only.

## Structural notes for the existing seed inputs

Per AegisGraph safety rules we describe seeds at the structural layer
only. The seed inputs (when present) are intentionally-malformed VP8L
lossless WebP files of the form documented in public CVE-2023-4863
research:

- A valid RIFF/WEBP/VP8L header advertising tiny canvas dimensions
  (typically <= 32x32 px so libFuzzer doesn't waste budget on
  allocation).
- A magic byte indicating lossless format.
- Transform headers + a color cache header.
- A code-length-encoding Huffman table whose code lengths are crafted
  such that the unpatched `BuildHuffmanTable` post-increments
  `offset[symbol_code_length]` past `MAX_ALLOWED_CODE_LENGTH` (15) and
  writes outside the on-stack `offset[]` array.

That structural shape is sufficient context for an auditor to confirm
the harness exercises CVE-2023-4863 specifically, without us shipping
the bytes that would let an attacker reproduce a working OOB write
against a deployed target.

## When the toolchain is unavailable

If clang / cmake / libFuzzer aren't installed on the current host,
`build.sh` aborts with `REPROCHAIN_REASON=blocked_pending_toolchain`
and the orchestrator records this in `build_manifest.json`. In that
case `MANIFEST.json` may be empty (no seeds listed) — the manifest
is still valid JSON, just with an empty `seeds` array.
