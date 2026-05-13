"""The Element X MediaRepository JVM harness ships as a committed artifact —
not a runtime generation. This is the second concrete JVM artifact shipped
under M5.1b, mirror to the Signal LinkPreviewUtil (M5.1) harness. Together
with Signal it satisfies the M7 "≥2 JVM" requirement.

After M5.1b lands, the following files MUST exist:

  reprochain/harness/element_x_media/MediaRepositoryFuzzer.java
  reprochain/harness/element_x_media/build.gradle
  reprochain/harness/element_x_media/manifest.json

The harness source MUST be the canonical Asemarefactor.md JVM-family
shape — fuzzerTestOneInput wrapping `MediaRepository.fetchAttachment`.
The build.gradle MUST pull only the media-attachment parser module +
Jazzer (NOT the full Element X Android application). The manifest MUST
be hash-only (no embedded bytes) and reference the harness source by
SHA-256.

This is an artifact-existence test. It does NOT build or run Jazzer; the
build / fuzz steps are a self-hosted-runner concern.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegisgraph.io import repo_root


HARNESS_DIR_REL = "reprochain/harness/element_x_media"


def _harness_dir() -> Path:
    return repo_root() / HARNESS_DIR_REL


def test_harness_dir_exists() -> None:
    assert _harness_dir().is_dir(), f"missing dir: {_harness_dir()}"


def test_harness_source_exists() -> None:
    path = _harness_dir() / "MediaRepositoryFuzzer.java"
    assert path.is_file(), f"missing harness source: {path}"
    assert path.stat().st_size > 0


def test_harness_source_calls_fetch_attachment() -> None:
    """Per Asemarefactor.md lines 168-186 the harness wraps
    MediaRepository.fetchAttachment. Every key spec line must appear."""
    path = _harness_dir() / "MediaRepositoryFuzzer.java"
    body = path.read_text(encoding="utf-8")
    must_contain = [
        "package org.aegisgraph.fuzz;",
        "import com.code_intelligence.jazzer.api.FuzzedDataProvider;",
        "import io.element.android.libraries.matrix.api.media.MediaRepository;",
        "public class MediaRepositoryFuzzer {",
        "public static void fuzzerTestOneInput(FuzzedDataProvider data) {",
        "MediaRepository.fetchAttachment",
        "// expected; ignore",
    ]
    for needle in must_contain:
        assert needle in body, f"harness missing spec line: {needle!r}"


def test_harness_source_swallows_expected_exceptions() -> None:
    """Element X media decode commonly throws on truncated/garbage inputs;
    the harness must swallow at least the canonical expected types so the
    fuzzer treats them as not-a-bug rather than novel crashes."""
    path = _harness_dir() / "MediaRepositoryFuzzer.java"
    body = path.read_text(encoding="utf-8")
    # Multi-catch must include at least one of the canonical expected types.
    assert "IllegalArgumentException" in body or "IOException" in body


def test_harness_build_gradle_exists() -> None:
    path = _harness_dir() / "build.gradle"
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    # Jazzer dependency + target parser module + Java version
    assert "jazzer" in body.lower()
    assert "matrix" in body.lower() or "media" in body.lower()
    assert "17" in body


def test_harness_build_gradle_does_not_pull_full_app() -> None:
    """The Gradle stub must NOT pull the full Element-X-Android app."""
    path = _harness_dir() / "build.gradle"
    body = path.read_text(encoding="utf-8").lower()
    forbidden_substrings = (
        "element-x-android:app",
        "element-x-android/app",
        "elementx-android:app",
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
    assert data["harness_id"] == "MediaRepositoryFuzzer"
    assert "harness_source_sha256" in data
    assert len(data["harness_source_sha256"]) == 64


def test_harness_manifest_records_jvm_engine() -> None:
    """The manifest documents the fuzzer engine + entry method so triage
    knows this is a JVM harness, not a native or Rust one."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert data["fuzzer_engine"] == "jazzer"
    assert data["entry_method"] == "fetchAttachment"
    assert "MediaRepository" in data["target_class"]


def test_harness_manifest_records_path_id() -> None:
    """The manifest carries the path_id so crash records can cite it."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert data["path_id"] == "element_x_media"


def test_harness_manifest_records_expected_exceptions() -> None:
    """The manifest documents the swallowed exception set — triage uses
    this to distinguish 'expected' vs novel crashes."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    expected = data.get("expected_exceptions", [])
    assert len(expected) >= 1, "expected_exceptions must list at least one type"


def test_harness_manifest_has_no_raw_bytes() -> None:
    """Manifest is hash-only — no bytes_b64, payload, etc."""
    raw = (_harness_dir() / "manifest.json").read_text(encoding="utf-8")
    for forbidden in ("bytes_b64", "payload_b64", "raw_bytes", "raw_witness"):
        assert forbidden not in raw, f"manifest leaks {forbidden}"


def test_harness_source_has_generator_comment() -> None:
    """Generated harnesses must mark themselves so a human reviewer can
    tell at a glance that the file is regenerable, not hand-written."""
    path = _harness_dir() / "MediaRepositoryFuzzer.java"
    body = path.read_text(encoding="utf-8").lower()
    assert "auto-generated" in body or "generated by" in body
    assert "harnessgen" in body
