"""The libwebp first harness ships as a committed artifact, not a runtime
generation.

After M3.1 lands, the following files MUST exist:

  reprochain/harness/libwebp/WebPDecodeRGB.harness.cc
  reprochain/harness/libwebp/Makefile
  reprochain/harness/libwebp/manifest.json

The harness source MUST be the canonical Asemarefactor.md lines 215-225
shape — LLVMFuzzerTestOneInput wrapping WebPDecodeRGB. The Makefile MUST
contain ASAN + UBSan + libfuzzer flags. The manifest MUST be hash-only
(no embedded bytes) and reference the harness source by SHA-256.

This is an artifact-existence test. It does NOT build the harness (clang +
libwebp headers + libfuzzer support aren't required to run pytest); the
build step is a self-hosted-runner concern.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegisgraph.io import repo_root


HARNESS_DIR_REL = "reprochain/harness/libwebp"


def _harness_dir() -> Path:
    return repo_root() / HARNESS_DIR_REL


def test_harness_dir_exists() -> None:
    assert _harness_dir().is_dir(), f"missing dir: {_harness_dir()}"


def test_harness_source_exists() -> None:
    path = _harness_dir() / "WebPDecodeRGB.harness.cc"
    assert path.is_file(), f"missing harness source: {path}"
    assert path.stat().st_size > 0


def test_harness_source_calls_webp_decode_rgb() -> None:
    """Per Asemarefactor.md lines 215-225 the harness wraps WebPDecodeRGB
    (NOT WebPDecodeRGBA — that's the legacy reprochain harness). This
    keeps the first generated artifact aligned with the spec template."""
    path = _harness_dir() / "WebPDecodeRGB.harness.cc"
    body = path.read_text(encoding="utf-8")
    assert "WebPDecodeRGB" in body
    assert "LLVMFuzzerTestOneInput" in body
    assert "WebPFree" in body
    assert '#include <webp/decode.h>' in body


def test_harness_makefile_exists() -> None:
    path = _harness_dir() / "Makefile"
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    assert "fuzzer" in body
    assert "address" in body
    assert "undefined" in body
    assert "trace-pc-guard" in body


def test_harness_manifest_exists_and_is_json() -> None:
    path = _harness_dir() / "manifest.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_harness_manifest_has_source_hash() -> None:
    """The manifest references the harness source by SHA-256 — no embedded
    bytes ever."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert "harness_id" in data
    assert data["harness_id"] == "WebPDecodeRGB"
    assert "harness_source_sha256" in data
    assert len(data["harness_source_sha256"]) == 64


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
