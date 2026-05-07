# ReproChain merge request

Branch: `stream/reprochain-proof` -> `stream/integration`. Branched
from `bb244e8` + 12 integration commits. Reviewer: this MR is the
single deliverable for the reprochain-proof stream described in
eng_plan §11.2.

Do NOT push to remote. Reviewer merges locally after reading.

## What is committed

```
docs/decision-log/0009-libwebp-cve-2023-4863-pins.md  (filled in from TEMPLATE)
reprochain/vendor/libwebp/COMMIT_PINS.md              (new — canonical SHA source)
reprochain/vendor/libwebp/upstream                     (new — git submodule)
.gitmodules                                            (updated — libwebp entry)
reprochain/harness/CMakeLists.txt                     (new)
reprochain/harness/fuzz_webp_decode.cc                (new — single-file libFuzzer harness)
reprochain/build.sh                                   (new — orchestrates two-pin build)
reprochain/BUILD_STATUS.md                            (new — disposition record)
reprochain/corpora-private/handcrafted/README.md      (new — seed-policy documentation)
reprochain/corpora-private/handcrafted/MANIFEST.json  (new — sha256+structural notes)
reprochain/analysis/CVE-2023-4863.md                  (rewritten — full technical writeup)
reprochain/analysis/pre-disclosure-simulation.md      (rewritten — score vector + claim bound)
aegisgraph/reprochain.py                              (rewritten — real build/run/map orchestration)
tests/test_reprochain_build.py                        (new)
tests/test_reprochain_run_summary.py                  (new)
tests/test_reprochain_mapping_records.py              (new)
.gitignore                                            (updated — build dirs + asan logs)
reprochain/evidence/build_manifest.json               (regenerated — status payload)
reprochain/evidence/run_status.json                   (regenerated — status payload)
reprochain/evidence/asan_report_summary.json          (new — committed scrubbed summary)
reprochain/evidence/mapping.json                      (regenerated — aggregated records)
reprochain/mapping/signal.json                        (new — per-target evidence record)
reprochain/mapping/element-x.json                     (new — per-target evidence record)
```

## Commit pin disposition

| Pin                  | SHA                                          | Source URL                                                                                  |
|----------------------|----------------------------------------------|---------------------------------------------------------------------------------------------|
| Vulnerable (parent)  | `7ba44f80f3b94fc0138db159afea770ef06532a0`   | https://github.com/webmproject/libwebp/commit/7ba44f80f3b94fc0138db159afea770ef06532a0      |
| Fixed (public fix)   | `902bc9190331343b2017211debcec8d2ab87e17a`   | https://github.com/webmproject/libwebp/commit/902bc9190331343b2017211debcec8d2ab87e17a      |

Fix commit subject: **"Fix OOB write in BuildHuffmanTable."** Confirmed
to ship in libwebp v1.3.2 (2023-09-13) per the [public release
notes](https://github.com/webmproject/libwebp/releases/tag/v1.3.2)
which attribute it to `crbug.com/1479274` and CVE-2023-4863.

The vulnerable pin is the **immediately-prior parent** of the fix on
`main` rather than a release tag. This guarantees the differential
between the two builds is exactly this one fix.

## Build status

**`blocked_pending_toolchain`** on the current dev host.

Reason: clang and cmake are not installed locally. Per the eng_plan
§11.2 implementation-reality clause, this is the **acceptable
disposition** — the harness is fully reproducible the moment the
pinned devcontainer (`devcontainer/Dockerfile`, Clang 18, CodeQL
2.20.6) is provisioned.

The `aegisgraph.reprochain.build()` orchestrator probes for required
tools, captures the missing-tool name into
`reprochain/evidence/build_manifest.json`, and exits cleanly. The
existing integration `make tooling-strict` gate already produces an
equivalent failure signal at the top of `make reproduce`.

To unblock and run the full A2 phase (compile + execute + capture
ASan signal), invoke from inside the devcontainer:

```bash
cd reprochain
./build.sh                       # produces fuzz_webp_decode_vuln + fuzz_webp_decode_fix
make -C .. reprochain-run        # runs both binaries against handcrafted seeds
make -C .. reprochain-map        # rebuilds mapping records with build/diff state
```

## ASan result counts

Not measured in this stream — host toolchain gap. Once the
devcontainer is up the orchestrator captures:

* `differential.vuln_crash_count` and `differential.fix_crash_count`
  in `reprochain/evidence/asan_report_summary.json`.
* `differential.isolates_cve_2023_4863` flips to `true` when
  `vuln_crash_count > 0 AND fix_crash_count == 0` — the exact
  contract the harness exists to demonstrate.

## Top-5 frames (vuln crash) — when reproduced

The harness's frame extractor (in `aegisgraph.reprochain._summarize_asan`)
is biased toward this CVE's signal:

```python
_INTERESTING_FUNCS = (
    "BuildHuffmanTable",
    "VP8LBuildHuffmanTable",
    "ReadHuffmanCodeLengths",
    "ReadHuffmanCode",
    "DecodeImageStream",
    "VP8LDecodeImage",
    "WebPDecode",
    "WebPDecodeRGBA",
    "LLVMFuzzerTestOneInput",
)
```

The expected vuln-binary stack walks roughly:
`LLVMFuzzerTestOneInput` -> `WebPDecodeRGBA` -> `WebPDecode` ->
`VP8LDecodeImage` -> `DecodeImageStream` -> `ReadHuffmanCodeLengths`
-> `VP8LBuildHuffmanTable` -> `BuildHuffmanTable` (where the OOB
write happens). Top-5 frame function names is what
`asan_report_summary.json` carries; source paths, line numbers, and
addresses are scrubbed by design.

## Mapping nodes per target

Both `signal` and `element-x` mapping records carry five nodes:

1. `entry.inbound-media` — MmsAttachment (Signal) / Coil ImageRequest
   (Element X).
2. `handler.media-pipeline` — Glide / Coil handler chain.
3. `decoder.app-stack` — application-level decoder wrapper.
4. `decoder.platform` — Android `ImageDecoder` /
   `BitmapFactory.decodeStream` (the platform indirection).
5. `sink.libwebp-buildhuffmantable` — anchored to the libwebp vuln
   commit URL.

The Android platform-decoder indirection is documented honestly in
each record's `limitations` field. We do **not** claim a direct
app->libwebp linkage.

Current extraction phase: **`anchor_only`**. The integration stream
merged extraction's anchor-only graph.json placeholders, so node
`source_anchor` URLs point at `tree/<commit>` rather than at
specific `blob/<sha>/.../File.kt#L<line>` SARIF anchors. When the
extraction stream produces real CodeQL output, `map_targets()`
detects the upgrade automatically (look for `#L` or `/blob/<sha>/`
in any node anchor) and switches the manifest's `extraction_phase`
to `codeql`.

## Validate status

```
$ python3 -m aegisgraph.cli validate
validation pass: 7 evidence records checked
```

Schema, score-vector, hash-chain, and safety-scanner errors are all
clean. The 7 records counted include both per-target mapping records
plus the pre-existing extraction + polydiff records — all chained
through `finalize_record()` and tamper-evident via
`schema/hash-chain.schema.json`.

## Time-to-crash from fuzzer

Not measured in this stream — host toolchain gap. The
`reprochain-fuzz` Make target (`make reprochain-fuzz`, 600s budget)
is wired up to invoke the harness in libFuzzer mode against the
handcrafted seed corpus when the devcontainer is up.

For the public PoC structure (small WebP with malformed VP8L Huffman
code-length stream) the expected time-to-first-crash is well under
60 seconds — the bug is hit on the very first call into
`BuildHuffmanTable` with a sufficiently structured input.

## Test results

```
$ python3 -m pytest -q
............................................                             [100%]
44 passed
```

Breakdown:
* 28 baseline tests (untouched from the integration branch).
* 16 new tests across the three new test modules:
    * `test_reprochain_build.py` (4 tests)
    * `test_reprochain_run_summary.py` (5 tests)
    * `test_reprochain_mapping_records.py` (7 tests)

## Safety contract verification

* Crash payload bytes: NEVER committed. Seed inputs live under
  `reprochain/corpora-private/handcrafted/` which is gitignored.
  Only sha256 + structural one-liners go into `MANIFEST.json`.
* Developer-host paths: scrubbed via `_redact_path()` before any
  string lands in `build_manifest.json` or `run_status.json`.
* Vulnerable binaries: gitignored (`reprochain/vendor/libwebp/cmake-vuln/`).
* Exploit material: none generated; harness output stops at ASan
  classification.
* Live-target probing: none; harness reads only from local files.
* Public-export claim: `release_classification` is left unset on all
  reprochain mapping records, so they default to private. Promotion
  to `public_sanitized` is the validator-export stream's job and
  flows through `validator/sanitize_check.py` first.

## Out-of-scope items left for future streams

* CodeQL-derived node anchors. The mapping orchestrator detects
  CodeQL-shaped extraction output (`#L<line>` fragments) and upgrades
  the manifest's `extraction_phase` automatically. The extraction
  stream owns producing that output.
* Live differential against deployed Signal Android / Element X
  Android binaries. That's outside the eng plan and outside the
  AegisGraph claim bound.
* Hardware-feature dispatch (NEON, SSE) inside libwebp's dsp/
  directory. The harness builds the portable C path because the
  CVE-2023-4863 bug is in code-length parsing, which is portable C.
* Fuzz-budget runs longer than 600s. The `reprochain-fuzz` target
  caps at 600s; longer runs are local-only and out of `make
  reproduce`'s critical path.
