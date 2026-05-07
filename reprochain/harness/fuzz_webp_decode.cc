// reprochain/harness/fuzz_webp_decode.cc
//
// libFuzzer + AddressSanitizer entrypoint for the AegisGraph ReproChain
// libwebp CVE-2023-4863 differential.
//
// This is the only fuzz harness source file in the repo. It is built
// twice by reprochain/build.sh:
//   * linked against libwebp-vuln.a (parent of the fix) -> fuzz_webp_decode_vuln
//   * linked against libwebp-fix.a (the public fix)     -> fuzz_webp_decode_fix
//
// Public API only. We deliberately do NOT call internal symbols like
// VP8LBuildHuffmanTable directly. The goal is to show that crafted WebP
// bytes drive the public WebPDecode entrypoint into the vulnerable
// BuildHuffmanTable path on the pre-fix tree, which mirrors how a real
// caller (Android ImageDecoder, a browser, Coil/Glide via the system
// codec) reaches the bug.
//
// Claim bound: ASan-classified memory-corruption signal only. No
// exploit gadgets, no process escape, no targeting of a deployed
// application. See docs/decision-log/0009-libwebp-cve-2023-4863-pins.md.

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "webp/decode.h"

// Cap canvas dimensions. WebP headers can claim multi-gigapixel
// canvases at ~6 bytes of cost; a naive decoder will OOM the host
// before the harness explores anything interesting. The CVE-2023-4863
// PoC uses tiny canvases (the bug is in code length parsing, not in
// pixel allocation), so this cap loses no coverage of the target
// crash class.
constexpr int kMaxWidth  = 4096;
constexpr int kMaxHeight = 4096;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // 30 bytes is the minimum WebP container; below that WebPGetInfo
  // hard-rejects and we'd just be exercising the rejection path.
  if (size < 30) {
    return 0;
  }

  // Peek at the header. WebPGetInfo is allocation-free and parses
  // enough of RIFF + VP8X/VP8L/VP8 chunks to learn (width, height).
  // It does NOT yet enter BuildHuffmanTable; that happens later in
  // WebPDecodeRGBA below.
  int width  = 0;
  int height = 0;
  if (!WebPGetInfo(data, size, &width, &height)) {
    return 0;
  }
  if (width <= 0 || height <= 0 ||
      width > kMaxWidth || height > kMaxHeight) {
    return 0;
  }

  // Drive the full decode. WebPDecodeRGBA is the high-level "decode
  // everything" entrypoint and returns a heap RGBA buffer on success
  // or NULL on any decoder failure. In the vulnerable tree the OOB
  // write inside BuildHuffmanTable happens BEFORE this call can
  // return; ASan intercepts and aborts at that frame, which is exactly
  // the signal we're after.
  //
  // We use this top-level entrypoint rather than incremental decode
  // (WebPIDec...) because the public PoC targets full-file decode and
  // because mobile callers (Glide, Coil, Android ImageDecoder) all
  // drive libwebp via a single WebPDecode-shaped call. Mirroring that
  // call site keeps the harness honest about what the reachability
  // argument actually claims.
  int out_width  = 0;
  int out_height = 0;
  uint8_t* rgba = WebPDecodeRGBA(data, size, &out_width, &out_height);

  // On the fix build any malformed input returns NULL here without
  // ASan signal. On the vuln build a malicious code-length stream
  // never reaches this line — ASan trips inside BuildHuffmanTable.
  if (rgba != nullptr) {
    WebPFree(rgba);
  }
  return 0;
}
