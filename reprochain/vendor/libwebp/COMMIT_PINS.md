# libwebp commit pins for CVE-2023-4863 ReproChain

This file is the canonical source for the two libwebp commit hashes the
ReproChain harness builds against. The build script
(`reprochain/build.sh`) reads these values and checks each one out into
its own build directory under `reprochain/vendor/libwebp/upstream/`,
which is a git submodule pointing at upstream
`https://github.com/webmproject/libwebp`.

## Vulnerable commit

```
SHA (full):   7ba44f80f3b94fc0138db159afea770ef06532a0
SHA (short):  7ba44f8
URL:          https://github.com/webmproject/libwebp/commit/7ba44f80f3b94fc0138db159afea770ef06532a0
```

This is the commit immediately preceding the public CVE-2023-4863 fix
on libwebp `main`. At this revision the lossless decoder's Huffman
table construction (`BuildHuffmanTable` in `src/utils/huffman_utils.c`)
contains the unbounded `offset[]` post-increment that produces the
heap out-of-bounds write the public exploit triggers. Building this
revision under AddressSanitizer is the **vulnerable** harness target
(`fuzz_webp_decode_vuln`).

## Fix commit

```
SHA (full):   902bc9190331343b2017211debcec8d2ab87e17a
SHA (short):  902bc91
URL:          https://github.com/webmproject/libwebp/commit/902bc9190331343b2017211debcec8d2ab87e17a
```

Commit subject: **"Fix OOB write in BuildHuffmanTable."**

Commit message body (verbatim from upstream):

> First, BuildHuffmanTable is called to check if the data is valid. If
> it is and the table is not big enough, more memory is allocated. This
> will make sure that valid (but unoptimized because of unbalanced
> codes) streams are still decodable.
>
> Bug: chromium:1479274
> Change-Id: I31c36dbf3aa78d35ecf38706b50464fd3d375741

This is the public, upstream fix referenced from
[NVD CVE-2023-4863](https://nvd.nist.gov/vuln/detail/CVE-2023-4863) and
shipped in [libwebp v1.3.2](https://github.com/webmproject/libwebp/releases/tag/v1.3.2)
on 2023-09-13. Building this revision under AddressSanitizer is the
**fixed** harness target (`fuzz_webp_decode_fix`).

## One-line rationale

We pin the **immediately-prior parent** of the public fix as the
vulnerable target (rather than an older release like v1.3.1) because
the differential is then *exactly* CVE-2023-4863 — every other line in
the two trees is identical, so any ASAN signal we observe in the
vulnerable build that does not appear in the fixed build is
attributable to this fix and only this fix.

## How the build script consumes these pins

`reprochain/build.sh` does, in order:

1. `cd reprochain/vendor/libwebp/upstream && git fetch --tags`
2. `git worktree add ../build-vuln 7ba44f80f3b94fc0138db159afea770ef06532a0`
3. `git worktree add ../build-fix  902bc9190331343b2017211debcec8d2ab87e17a`
4. CMake-configures both worktrees with `-O1 -g -fsanitize=address,fuzzer`
   and `-DWEBP_BUILD_LIBWEBPMUX=OFF`.
5. Builds `libwebp-vuln.a` and `libwebp-fix.a` into separate build dirs
   (`build-vuln/`, `build-fix/`).
6. Compiles `reprochain/harness/fuzz_webp_decode.cc` twice, linking
   against each archive, producing `fuzz_webp_decode_vuln` and
   `fuzz_webp_decode_fix`.

The pins live in this file (not in `build.sh`) so a future pin update
goes through code review on this single file.

## Sources

- NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-4863
- libwebp upstream Git: https://github.com/webmproject/libwebp
- v1.3.2 release notes: https://github.com/webmproject/libwebp/releases/tag/v1.3.2
- Chromium bug: https://bugs.chromium.org/p/chromium/issues/detail?id=1479274
- Upstream fix commit: https://github.com/webmproject/libwebp/commit/902bc9190331343b2017211debcec8d2ab87e17a
