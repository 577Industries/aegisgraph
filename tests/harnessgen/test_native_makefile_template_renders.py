"""The native.Makefile.j2 template renders a Makefile with ASAN + UBSan
+ libfuzzer build flags per Asemarefactor.md line 226.

Build flags must include:
  -fsanitize=address,undefined
  -fsanitize=fuzzer  (or equivalent libfuzzer link)
  -fsanitize-coverage=trace-pc-guard

The Makefile is a build recipe, not a runner. Tests check structure only;
they do NOT invoke make.
"""

from __future__ import annotations

from aegisgraph.harnessgen.templates import render_native_makefile


def _webp_context() -> dict:
    return {
        "harness_id": "WebPDecodeRGB",
        "harness_source": "WebPDecodeRGB.harness.cc",
        "harness_binary": "WebPDecodeRGB_fuzzer",
        "header_include_dirs": ["/usr/include/webp", "/opt/libwebp/include"],
        "link_libs": ["webp", "webpdemux", "sharpyuv"],
        "compiler": "clang++",
    }


def test_makefile_has_target() -> None:
    rendered = render_native_makefile(_webp_context())
    assert "WebPDecodeRGB_fuzzer" in rendered


def test_makefile_uses_clangxx() -> None:
    rendered = render_native_makefile(_webp_context())
    assert "clang++" in rendered


def test_makefile_emits_asan_flag() -> None:
    rendered = render_native_makefile(_webp_context())
    # Both "address,undefined" or split flags acceptable; just need both
    # sanitizers present.
    assert "address" in rendered
    assert "undefined" in rendered


def test_makefile_emits_libfuzzer_flag() -> None:
    rendered = render_native_makefile(_webp_context())
    assert "fuzzer" in rendered


def test_makefile_emits_coverage_flag() -> None:
    rendered = render_native_makefile(_webp_context())
    # Asemarefactor.md line 226 calls out trace-pc-guard specifically.
    assert "trace-pc-guard" in rendered


def test_makefile_links_libwebp() -> None:
    rendered = render_native_makefile(_webp_context())
    assert "-lwebp" in rendered


def test_makefile_has_clean_target() -> None:
    rendered = render_native_makefile(_webp_context())
    assert "clean:" in rendered


def test_makefile_no_live_target_probing() -> None:
    """Defense-in-depth: Makefile must NOT contain commands that download
    live target binaries or probe external services. This is a build recipe
    for a sandboxed harness only."""
    rendered = render_native_makefile(_webp_context())
    forbidden = ("nmap", "masscan", "curl http", "wget http")
    lowered = rendered.lower()
    for token in forbidden:
        assert token not in lowered, f"Makefile contains forbidden token: {token}"
