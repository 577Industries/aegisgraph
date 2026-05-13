"""The Signal LinkPreviewUtil JVM harness ships as a committed artifact —
not a runtime generation. This is the canonical M5.1 concrete artifact,
mirror to the libwebp/WebPDecodeRGB harness from M3.1.

After M5.1 lands, the following files MUST exist:

  reprochain/harness/signal_linkpreview/LinkPreviewUtilFuzzer.java
  reprochain/harness/signal_linkpreview/build.gradle
  reprochain/harness/signal_linkpreview/manifest.json

The harness source MUST be the canonical Asemarefactor.md lines 168-186
shape — fuzzerTestOneInput wrapping LinkPreviewUtil.findValidPreviewUrls.
The build.gradle MUST pull only the parser module + Jazzer (NOT the full
Signal Android app). The manifest MUST be hash-only (no embedded bytes)
and reference the harness source by SHA-256.

This is an artifact-existence test. It does NOT build or run Jazzer; the
build / fuzz steps are a self-hosted-runner concern.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegisgraph.io import repo_root


HARNESS_DIR_REL = "reprochain/harness/signal_linkpreview"


def _harness_dir() -> Path:
    return repo_root() / HARNESS_DIR_REL


def test_harness_dir_exists() -> None:
    assert _harness_dir().is_dir(), f"missing dir: {_harness_dir()}"


def test_harness_source_exists() -> None:
    path = _harness_dir() / "LinkPreviewUtilFuzzer.java"
    assert path.is_file(), f"missing harness source: {path}"
    assert path.stat().st_size > 0


def test_harness_source_calls_link_preview_util() -> None:
    """Per Asemarefactor.md lines 168-186 the harness wraps
    LinkPreviewUtil.findValidPreviewUrls. Every key spec line must appear."""
    path = _harness_dir() / "LinkPreviewUtilFuzzer.java"
    body = path.read_text(encoding="utf-8")
    must_contain = [
        "package org.aegisgraph.fuzz;",
        "import com.code_intelligence.jazzer.api.FuzzedDataProvider;",
        "import org.thoughtcrime.securesms.linkpreview.LinkPreviewUtil;",
        "public class LinkPreviewUtilFuzzer {",
        "public static void fuzzerTestOneInput(FuzzedDataProvider data) {",
        "String input = data.consumeRemainingAsString();",
        "LinkPreviewUtil.findValidPreviewUrls(input);",
        "IllegalArgumentException",
        "StringIndexOutOfBoundsException",
        "// expected; ignore",
    ]
    for needle in must_contain:
        assert needle in body, f"harness missing spec line: {needle!r}"


def test_harness_build_gradle_exists() -> None:
    path = _harness_dir() / "build.gradle"
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    # Jazzer dependency + target parser module + Java version
    assert "jazzer" in body.lower()
    assert "link-preview-parser" in body
    assert "17" in body


def test_harness_build_gradle_does_not_pull_full_app() -> None:
    """The Gradle stub must NOT pull the full Signal-Android app."""
    path = _harness_dir() / "build.gradle"
    body = path.read_text(encoding="utf-8").lower()
    forbidden_substrings = (
        "signal-android:app",
        "signal-android/app",
    )
    for token in forbidden_substrings:
        assert token not in body, f"gradle pulls full app via {token}"


def test_harness_manifest_exists_and_is_json() -> None:
    path = _harness_dir() / "manifest.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_harness_manifest_has_source_hash() -> None:
    """The manifest references the harness source by SHA-256 — no embedded
    bytes ever."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert data["harness_id"] == "LinkPreviewUtilFuzzer"
    assert "harness_source_sha256" in data
    assert len(data["harness_source_sha256"]) == 64


def test_harness_manifest_records_jvm_engine() -> None:
    """The manifest documents the fuzzer engine + entry method so triage
    knows this is a JVM harness, not a native one."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert data["fuzzer_engine"] == "jazzer"
    assert data["entry_method"] == "findValidPreviewUrls"
    assert data["target_class"] == "org.thoughtcrime.securesms.linkpreview.LinkPreviewUtil"


def test_harness_manifest_has_no_raw_bytes() -> None:
    """Manifest is hash-only — no bytes_b64, payload, etc."""
    raw = (_harness_dir() / "manifest.json").read_text(encoding="utf-8")
    for forbidden in ("bytes_b64", "payload_b64", "raw_bytes", "raw_witness"):
        assert forbidden not in raw, f"manifest leaks {forbidden}"


def test_harness_manifest_records_path_id() -> None:
    """The manifest carries the path_id so crash records can cite it."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert data["path_id"] == "signal_linkpreview"


def test_harness_manifest_records_expected_exceptions() -> None:
    """The manifest documents the swallowed exception set — triage uses
    this to distinguish 'expected' vs novel crashes."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    expected = data.get("expected_exceptions", [])
    assert "IllegalArgumentException" in expected
    assert "StringIndexOutOfBoundsException" in expected
