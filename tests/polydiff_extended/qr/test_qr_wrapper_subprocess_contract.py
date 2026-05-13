"""Wrapper-subprocess contract tests for the qr family.

Each qr wrapper (zxing_cli, zbar_cli, apple_vision_stub, ios_detector_stub)
is a subprocess that:

  * Reads the witness QR image bytes from stdin.
  * Writes a single JSON line to stdout matching
    schema/fact-vector-qr.schema.json.
  * Exits 0 on success; non-zero exits are converted to a
    `_crash_envelope`-equivalent fact-vector with
    decode_outcome.status=parse_error and
    parser_warnings=["wrapper crash recorded as a Finding"].

When the underlying parser binary is NOT available (no ZXing / ZBar in
the devcontainer, Apple Vision on non-macOS, iOS Camera always), the
wrapper returns a degenerate fact-vector with binary_missing=true and
decode_outcome.status=parse_error. Tests mock subprocess.run so they
exercise wrapper logic without requiring any installed parsers.

The Apple Vision and iOS detector wrappers are stubs that ALWAYS return
a binary_missing envelope in the devcontainer (no Apple toolchain
available); they're parameterized identically so the contract is
uniform across the family.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest


from aegisgraph.polydiff.families.qr.wrappers import (
    apple_vision_stub,
    ios_detector_stub,
    zbar_cli,
    zxing_cli,
)


WRAPPER_MODULES = {
    "zxing_cli": zxing_cli,
    "zbar_cli": zbar_cli,
    "apple_vision_stub": apple_vision_stub,
    "ios_detector_stub": ios_detector_stub,
}

WRAPPERS = [
    ("zxing_cli", "zxing_cli"),
    ("zbar_cli", "zbar_cli"),
    ("apple_vision_stub", "apple_vision_stub"),
    ("ios_detector_stub", "ios_detector_stub"),
]


def _import_wrapper(module_name: str):
    if module_name not in WRAPPER_MODULES:
        raise KeyError(
            f"unknown qr wrapper module {module_name!r}; "
            f"expected one of {sorted(WRAPPER_MODULES)}"
        )
    return WRAPPER_MODULES[module_name]


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_module_importable(profile: str, module_name: str) -> None:
    mod = _import_wrapper(module_name)
    assert hasattr(mod, "run"), (
        f"qr wrapper {module_name} must expose a `run(witness_bytes, "
        f"input_id) -> dict` callable"
    )


# zxing_cli and zbar_cli are real subprocess wrappers; the two stubs return
# binary_missing directly without invoking subprocess.run.
SUBPROCESS_WRAPPERS = [
    ("zxing_cli", "zxing_cli"),
    ("zbar_cli", "zbar_cli"),
]


@pytest.mark.parametrize("profile,module_name", SUBPROCESS_WRAPPERS)
def test_wrapper_run_returns_dict_with_required_axes(
    profile: str, module_name: str, monkeypatch
) -> None:
    """A successful binary invocation returns a dict containing each of the
    10 qr-family axes. Mock subprocess.run to return a synthetic JSON line
    that mimics the binary's expected output."""
    mod = _import_wrapper(module_name)

    sample_stdout = json.dumps(
        {
            "input_id": "QR-TEST-001",
            "parser_profile": profile,
            "schema_version": "v1.0",
            "detected_text": "https://example.com/x",
            "ecc_level": "M",
            "version": 4,
            "mode": "byte",
            "encoding_charset": "UTF-8",
            "structured_append_index": None,
            "structured_append_total": None,
            "fnc1_present": False,
            "parser_warnings": [],
            "decode_outcome": {"status": "ok", "bytes_out": 21},
        }
    )

    class FakeCompleted:
        returncode = 0
        stdout = sample_stdout.encode("utf-8")
        stderr = b""

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"\x89PNG\r\n\x1a\n", input_id="QR-TEST-001")
    assert isinstance(result, dict)
    for axis in (
        "detected_text",
        "ecc_level",
        "version",
        "mode",
        "encoding_charset",
        "structured_append_index",
        "structured_append_total",
        "fnc1_present",
        "parser_warnings",
        "decode_outcome",
    ):
        assert axis in result, f"{profile} wrapper missing axis {axis!r}"
    assert result["input_id"] == "QR-TEST-001"
    assert result["parser_profile"] == profile


@pytest.mark.parametrize("profile,module_name", SUBPROCESS_WRAPPERS)
def test_wrapper_binary_missing_returns_crash_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """When the underlying binary is not on PATH, the wrapper must catch
    FileNotFoundError and return a `_crash_envelope`-equivalent fact-vector
    with binary_missing=true and decode_outcome.status=parse_error."""
    mod = _import_wrapper(module_name)

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        raise FileNotFoundError(f"No such binary on PATH: {cmd[0]}")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"\x89PNG", input_id="QR-MISSING")
    assert isinstance(result, dict)
    assert result.get("binary_missing") is True, (
        f"{profile}: when binary absent, wrapper must set binary_missing=True"
    )
    assert result.get("decode_outcome", {}).get("status") == "parse_error", (
        f"{profile}: missing-binary envelope must record "
        f"decode_outcome.status=parse_error"
    )
    assert result.get("parser_profile") == profile
    assert result.get("input_id") == "QR-MISSING"


@pytest.mark.parametrize("profile,module_name", SUBPROCESS_WRAPPERS)
def test_wrapper_nonzero_exit_returns_crash_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """If the binary exits non-zero (e.g. unreadable image rejected), the
    wrapper must return a parse_error/decode_error envelope, NOT raise."""
    mod = _import_wrapper(module_name)

    class FakeCompleted:
        returncode = 1
        stdout = b""
        stderr = b"invalid qr image"

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"<BROKEN>", input_id="QR-BAD")
    assert result.get("decode_outcome", {}).get("status") in {
        "parse_error",
        "decode_error",
    }
    assert result.get("input_id") == "QR-BAD"
    assert result.get("parser_profile") == profile


# Stubs always return binary_missing — apple_vision_stub on non-macOS and
# ios_detector_stub on every platform.
STUB_WRAPPERS = [
    ("apple_vision_stub", "apple_vision_stub"),
    ("ios_detector_stub", "ios_detector_stub"),
]


@pytest.mark.parametrize("profile,module_name", STUB_WRAPPERS)
def test_stub_wrapper_always_returns_binary_missing_envelope(
    profile: str, module_name: str
) -> None:
    """apple_vision_stub and ios_detector_stub always emit a
    binary_missing envelope; no subprocess is invoked."""
    mod = _import_wrapper(module_name)
    result = mod.run(witness_bytes=b"\x89PNG", input_id="QR-STUB")
    assert isinstance(result, dict)
    assert result.get("binary_missing") is True, (
        f"{profile}: stub must always set binary_missing=True"
    )
    assert result.get("decode_outcome", {}).get("status") == "parse_error"
    assert result.get("parser_profile") == profile
    assert result.get("input_id") == "QR-STUB"


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_emits_schema_valid_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """The crash envelope produced by an absent binary must validate
    against schema/fact-vector-qr.schema.json."""
    mod = _import_wrapper(module_name)

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        raise FileNotFoundError(cmd[0])

    # Patch subprocess.run; the stubs will not call it but it's safe to mock.
    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"", input_id="QR-CONTRACT")

    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        pytest.skip("jsonschema not available")
    from aegisgraph.io import load_json, repo_root

    schema = load_json(repo_root() / "schema" / "fact-vector-qr.schema.json")
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(result), key=str)
    assert not errors, (
        f"{profile} crash envelope failed schema validation: "
        + "; ".join(
            f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors
        )
    )
