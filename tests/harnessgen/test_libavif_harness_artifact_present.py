"""The libavif avifDecoderRead native harness ships as a committed artifact —
not a runtime generation. This is the second concrete native artifact
shipped under M5.1b, mirror to the libwebp (M3.1) harness. Together with
libwebp it satisfies the M7 "≥2 native" requirement.

After M5.1b lands, the following files MUST exist:

  reprochain/harness/libavif/avifDecoderRead.harness.cc
  reprochain/harness/libavif/Makefile
  reprochain/harness/libavif/manifest.json

The harness source MUST be the canonical Asemarefactor.md image-family
shape — LLVMFuzzerTestOneInput wrapping `avifDecoderReadMemory` with the
paired avifDecoderCreate / avifImageCreateEmpty / avifImageDestroy /
avifDecoderDestroy setup-and-teardown. The Makefile MUST contain ASAN +
UBSan + libfuzzer flags (same flag-set as the libwebp Makefile). The
manifest MUST be hash-only (no embedded bytes) and reference the harness
source by SHA-256.

This is an artifact-existence test. It does NOT build the harness (clang +
libavif headers + libfuzzer support aren't required to run pytest); the
build step is a self-hosted-runner concern.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegisgraph.io import repo_root


HARNESS_DIR_REL = "reprochain/harness/libavif"


def _harness_dir() -> Path:
    return repo_root() / HARNESS_DIR_REL


def test_harness_dir_exists() -> None:
    assert _harness_dir().is_dir(), f"missing dir: {_harness_dir()}"


def test_harness_source_exists() -> None:
    path = _harness_dir() / "avifDecoderRead.harness.cc"
    assert path.is_file(), f"missing harness source: {path}"
    assert path.stat().st_size > 0


def test_harness_source_calls_avif_decoder_read_memory() -> None:
    """The harness wraps avifDecoderReadMemory and pairs each create call
    with its matching destroy. Every key spec line must appear."""
    path = _harness_dir() / "avifDecoderRead.harness.cc"
    body = path.read_text(encoding="utf-8")
    must_contain = [
        "#include <avif/avif.h>",
        'extern "C"',
        "LLVMFuzzerTestOneInput",
        "const uint8_t* data",
        "size_t size",
        "avifDecoderCreate",
        "avifImageCreateEmpty",
        "avifDecoderReadMemory",
        "avifImageDestroy",
        "avifDecoderDestroy",
        "return 0;",
    ]
    for needle in must_contain:
        assert needle in body, f"harness missing spec line: {needle!r}"


def test_harness_source_guards_allocations() -> None:
    """avifDecoderCreate / avifImageCreateEmpty can return NULL. The harness
    must check both and early-return without leaking the prior allocation."""
    path = _harness_dir() / "avifDecoderRead.harness.cc"
    body = path.read_text(encoding="utf-8")
    # At minimum the harness must check for the decoder and image being null
    # before invoking the read; if either is null, return early.
    assert "if (!decoder)" in body or "if (decoder == nullptr)" in body
    assert "if (!image)" in body or "if (image == nullptr)" in body


def test_harness_makefile_exists() -> None:
    path = _harness_dir() / "Makefile"
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    # Same sanitizer + libfuzzer set as the libwebp Makefile.
    assert "fuzzer" in body
    assert "address" in body
    assert "undefined" in body
    assert "trace-pc-guard" in body


def test_harness_makefile_links_libavif() -> None:
    """Native harness Makefile must -lavif so the linker resolves
    avifDecoderReadMemory + friends."""
    path = _harness_dir() / "Makefile"
    body = path.read_text(encoding="utf-8")
    assert "-lavif" in body or "lavif" in body


def test_harness_manifest_exists_and_is_json() -> None:
    path = _harness_dir() / "manifest.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_harness_manifest_has_source_hash() -> None:
    """The manifest references the harness source by SHA-256 — no embedded
    bytes ever."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert data["harness_id"] == "avifDecoderRead"
    assert "harness_source_sha256" in data
    assert len(data["harness_source_sha256"]) == 64


def test_harness_manifest_records_native_engine() -> None:
    """The manifest documents the fuzzer engine + entry function so triage
    knows this is a libFuzzer native harness."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert data["fuzzer_engine"] == "libfuzzer"
    assert data["entry_function"] == "avifDecoderReadMemory"
    assert data["header"] == "avif/avif.h"


def test_harness_manifest_records_path_id() -> None:
    """The manifest carries the path_id so crash records can cite it."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert data["path_id"] == "libavif"


def test_harness_manifest_has_no_raw_bytes() -> None:
    """Manifest is hash-only — no bytes_b64, payload, etc."""
    raw = (_harness_dir() / "manifest.json").read_text(encoding="utf-8")
    for forbidden in ("bytes_b64", "payload_b64", "raw_bytes", "raw_witness"):
        assert forbidden not in raw, f"manifest leaks {forbidden}"


def test_harness_manifest_records_sanitizer_config() -> None:
    """The manifest documents what sanitizers the harness is built with —
    triage-only metadata, not a build script."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    san = data.get("sanitizers", [])
    assert "address" in san
    assert "undefined" in san


def test_harness_source_has_generator_comment() -> None:
    """Generated harnesses must mark themselves so a human reviewer can
    tell at a glance that the file is regenerable, not hand-written."""
    path = _harness_dir() / "avifDecoderRead.harness.cc"
    body = path.read_text(encoding="utf-8").lower()
    assert "auto-generated" in body or "generated by" in body
    assert "harnessgen" in body
