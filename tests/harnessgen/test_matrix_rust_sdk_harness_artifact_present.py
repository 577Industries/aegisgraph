"""The matrix-rust-sdk MessageType Rust harness ships as a committed
artifact — not a runtime generation. This is the canonical M5.2 concrete
artifact, mirror to the libwebp (M3.1) and signal_linkpreview (M5.1)
harnesses.

After M5.2 lands, the following files MUST exist:

  reprochain/harness/matrix_rust_sdk_messagetype/fuzz_target_message_type.rs
  reprochain/harness/matrix_rust_sdk_messagetype/Cargo.toml
  reprochain/harness/matrix_rust_sdk_messagetype/fuzz/Cargo.toml
  reprochain/harness/matrix_rust_sdk_messagetype/manifest.json

The harness source MUST be the canonical Asemarefactor.md lines 230-238
shape — `fuzz_target!(|data: &[u8]| { let _ = serde_json::from_slice::<MessageType>(data); });`.
The Cargo.toml MUST pull only matrix-sdk + libfuzzer-sys + serde_json (NOT
the full Element X app). The manifest MUST be hash-only (no embedded
bytes) and reference the harness source by SHA-256.

This is an artifact-existence test. It does NOT build the harness; the
build / fuzz steps are a self-hosted-runner concern.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegisgraph.io import repo_root


HARNESS_DIR_REL = "reprochain/harness/matrix_rust_sdk_messagetype"


def _harness_dir() -> Path:
    return repo_root() / HARNESS_DIR_REL


def test_harness_dir_exists() -> None:
    assert _harness_dir().is_dir(), f"missing dir: {_harness_dir()}"


def test_harness_source_exists() -> None:
    path = _harness_dir() / "fuzz_target_message_type.rs"
    assert path.is_file(), f"missing harness source: {path}"
    assert path.stat().st_size > 0


def test_harness_source_calls_message_type_from_slice() -> None:
    """Per Asemarefactor.md lines 230-238 the harness wraps
    serde_json::from_slice::<MessageType>. Every key spec line must appear."""
    path = _harness_dir() / "fuzz_target_message_type.rs"
    body = path.read_text(encoding="utf-8")
    must_contain = [
        "#![no_main]",
        "use libfuzzer_sys::fuzz_target;",
        "use matrix_sdk::ruma::events::room::message::MessageType;",
        "fuzz_target!(|data: &[u8]| {",
        "let _ = serde_json::from_slice::<MessageType>(data);",
        "});",
    ]
    for needle in must_contain:
        assert needle in body, f"harness missing spec line: {needle!r}"


def test_harness_cargo_toml_exists() -> None:
    path = _harness_dir() / "Cargo.toml"
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    # Minimal deps: matrix-sdk + serde_json + libfuzzer-sys
    assert "matrix-sdk" in body
    assert "serde_json" in body
    assert "libfuzzer-sys" in body


def test_harness_cargo_toml_documents_placeholders() -> None:
    """The Cargo.toml uses placeholder pins for `matrix-sdk` version; the
    file must say so in a comment block so a reviewer can tell this is a
    stub awaiting M5.2.b."""
    path = _harness_dir() / "Cargo.toml"
    body = path.read_text(encoding="utf-8").lower()
    assert "placeholder" in body or "to be pinned" in body


def test_harness_cargo_toml_does_not_pull_full_app() -> None:
    """The Cargo.toml must NOT pull the full Element X application.
    Only the matrix-sdk crate (+ minimal fuzz deps) is allowed."""
    path = _harness_dir() / "Cargo.toml"
    body = path.read_text(encoding="utf-8").lower()
    forbidden_substrings = (
        "element-x",
        "elementx-android",
        "element_x_app",
    )
    for token in forbidden_substrings:
        assert token not in body, f"Cargo.toml pulls full app via {token}"


def test_harness_fuzz_subcrate_cargo_toml_exists() -> None:
    """cargo-fuzz convention puts the fuzz target in a nested fuzz/
    crate with its own Cargo.toml. Verify the nested manifest exists."""
    path = _harness_dir() / "fuzz" / "Cargo.toml"
    assert path.is_file(), f"missing nested fuzz crate manifest: {path}"
    body = path.read_text(encoding="utf-8")
    # The nested fuzz crate references libfuzzer-sys + the harness target.
    assert "libfuzzer-sys" in body
    # cargo-fuzz convention: [[bin]] entry with the fuzz target name.
    assert "[[bin]]" in body
    assert "fuzz_target_message_type" in body


def test_harness_manifest_exists_and_is_json() -> None:
    path = _harness_dir() / "manifest.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_harness_manifest_has_source_hash() -> None:
    """The manifest references the harness source by SHA-256 — no embedded
    bytes ever."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert data["harness_id"] == "matrix_rust_sdk_messagetype"
    assert "harness_source_sha256" in data
    assert len(data["harness_source_sha256"]) == 64


def test_harness_manifest_records_rust_engine() -> None:
    """The manifest documents the fuzzer engine + entry path so triage
    knows this is a Rust harness, not a native or JVM one."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert data["fuzzer_engine"] == "cargo-fuzz"
    assert data["target_crate"] == "matrix_sdk"
    assert (
        data["target_use_path"]
        == "ruma::events::room::message::MessageType"
    )


def test_harness_manifest_has_no_raw_bytes() -> None:
    """Manifest is hash-only — no bytes_b64, payload, etc."""
    raw = (_harness_dir() / "manifest.json").read_text(encoding="utf-8")
    for forbidden in ("bytes_b64", "payload_b64", "raw_bytes", "raw_witness"):
        assert forbidden not in raw, f"manifest leaks {forbidden}"


def test_harness_manifest_records_path_id() -> None:
    """The manifest carries the path_id so crash records can cite it."""
    data = json.loads((_harness_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert data["path_id"] == "matrix_rust_sdk_messagetype"


def test_harness_source_has_generator_comment() -> None:
    """Generated harnesses must mark themselves so a human reviewer can
    tell at a glance that the file is regenerable, not hand-written."""
    path = _harness_dir() / "fuzz_target_message_type.rs"
    body = path.read_text(encoding="utf-8").lower()
    assert "auto-generated" in body or "generated by" in body
    assert "harnessgen" in body
