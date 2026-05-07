# ReproChain build status

Recorded by the reprochain-proof stream on 2026-05-07.

## Current host status: `blocked_pending_toolchain`

The reprochain-proof stream developed and committed every file needed
to build the libwebp CVE-2023-4863 differential harness — CMakeLists,
the libFuzzer `LLVMFuzzerTestOneInput` source, the orchestration
script, and the orchestrator under `aegisgraph/reprochain.py`. On the
current development host, however, `clang` and `cmake` are not
installed. `reprochain/build.sh` therefore probes for the required
tools and writes `reprochain/evidence/build_manifest.json` with:

```
{ "status": "blocked_pending_toolchain",
  "reason": "missing tool: cmake" (or clang, etc.) }
```

This is the **acceptable** disposition under the eng plan §11.2: the
harness is fully reproducible the moment the pinned devcontainer
(`devcontainer/Dockerfile`, Clang 18 + CodeQL 2.20.6 + ...) is
provisioned. Until then the integration stream's
`make tooling-strict` gate already fails loudly with a list of missing
pinned tools, which is the same signal `reprochain-build` surfaces.

## How to unblock

Run from inside the pinned devcontainer:

```bash
cd reprochain
./build.sh
```

The script will:

1. Initialize the `reprochain/vendor/libwebp/upstream` submodule (one
   shallow git fetch from `https://github.com/webmproject/libwebp`).
2. Resolve `git cat-file -t` against the pinned `7ba44f8` and
   `902bc91` SHAs (from `reprochain/vendor/libwebp/COMMIT_PINS.md`).
3. `git worktree add` each pin into `build-vuln/` and `build-fix/`.
4. Run cmake against `reprochain/harness/CMakeLists.txt` for each
   worktree, producing `libwebp-vuln.a`, `libwebp-fix.a`,
   `fuzz_webp_decode_vuln`, and `fuzz_webp_decode_fix`.
5. Smoke-check each binary: `-help=1` exits 0 and `nm | grep
   __asan_init` shows ASan was linked.
6. Print `REPROCHAIN_STATUS=ready` on success, which
   `aegisgraph/reprochain.py` writes into `build_manifest.json`.

After build success, run `make reprochain-run` to feed the harness
its handcrafted seed corpus and capture the differential ASan signal
into `reprochain/evidence/asan_report_summary.json`.

## Why the harness builds clean libwebp instead of using upstream's
## `make`

libwebp's upstream CMakeLists pulls in encoder, mux, and demux paths
this harness doesn't exercise. Dragging those in expands the build
surface (and the toolchain requirements: libpng, libtiff, etc.) for
no coverage benefit — the CVE-2023-4863 bug is in the lossless
**decoder**'s Huffman table construction. Our `harness/CMakeLists.txt`
compiles only the decoder TUs we walked from `WebPDecode` so the
build is minimal and the static archive is small.

## What is committed vs. transient

Committed (this stream's source-of-truth files):
- `reprochain/harness/CMakeLists.txt`
- `reprochain/harness/fuzz_webp_decode.cc`
- `reprochain/build.sh`
- `reprochain/vendor/libwebp/COMMIT_PINS.md`
- `.gitmodules` entry for the upstream libwebp submodule
- This `BUILD_STATUS.md`

Transient (gitignored — see `.gitignore`):
- `reprochain/vendor/libwebp/build-vuln/` (git worktree of vuln pin)
- `reprochain/vendor/libwebp/build-fix/`  (git worktree of fix pin)
- `reprochain/vendor/libwebp/cmake-vuln/` (CMake build dir)
- `reprochain/vendor/libwebp/cmake-fix/`  (CMake build dir)
- `reprochain/evidence/asan_*.txt` (raw ASan logs)
- All seed input files under `reprochain/corpora-private/handcrafted/`

Committed evidence (scrubbed):
- `reprochain/evidence/build_manifest.json` — build status only
- `reprochain/evidence/run_status.json`     — run summary only
- `reprochain/evidence/asan_report_summary.json` — crash count + top
   stack frame **function names** per binary; no payload bytes, no
   developer-host paths
- `reprochain/evidence/mapping.json`        — CodeQL-anchored mapping
   records when extraction has produced SARIF; placeholder
   anchor-only records otherwise
- `reprochain/corpora-private/handcrafted/MANIFEST.json` — list of
   seed-file sha256 hashes + structural one-liners
