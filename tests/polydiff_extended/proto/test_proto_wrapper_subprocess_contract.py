"""Wrapper-subprocess contract tests for the proto family.

Each proto wrapper (protoc_python, flatc_runner, msgpack_python,
protoc_gogofaster_stub) is a subprocess that:

  * Reads the witness binary message payload bytes from stdin.
  * Writes a single JSON line to stdout matching
    schema/fact-vector-proto.schema.json.
  * Exits 0 on success; non-zero exits are converted to a
    `_crash_envelope`-equivalent fact-vector with
    decode_outcome.status=parse_error and
    parser_warnings=["wrapper crash recorded as a Finding"].

When the underlying parser binary is NOT available (no protoc / flatc
in the devcontainer, gogo-protobuf always), the wrapper returns a
degenerate fact-vector with binary_missing=true and
decode_outcome.status=parse_error. Tests mock subprocess.run so they
exercise wrapper logic without requiring any installed parsers.

The gogofaster stub ALWAYS returns binary_missing in the devcontainer
(no gogo toolchain available).
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest


from aegisgraph.polydiff.families.proto.wrappers import (
    flatc_runner,
    msgpack_python,
    protoc_gogofaster_stub,
    protoc_python,
)


WRAPPER_MODULES = {
    "protoc_python": protoc_python,
    "flatc_runner": flatc_runner,
    "msgpack_python": msgpack_python,
    "protoc_gogofaster_stub": protoc_gogofaster_stub,
}

WRAPPERS = [
    ("protoc_python", "protoc_python"),
    ("flatc_runner", "flatc_runner"),
    ("msgpack_python", "msgpack_python"),
    ("protoc_gogofaster_stub", "protoc_gogofaster_stub"),
]


def _import_wrapper(module_name: str):
    if module_name not in WRAPPER_MODULES:
        raise KeyError(
            f"unknown proto wrapper module {module_name!r}; "
            f"expected one of {sorted(WRAPPER_MODULES)}"
        )
    return WRAPPER_MODULES[module_name]


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_module_importable(profile: str, module_name: str) -> None:
    mod = _import_wrapper(module_name)
    assert hasattr(mod, "run"), (
        f"proto wrapper {module_name} must expose a `run(witness_bytes, "
        f"input_id) -> dict` callable"
    )


# protoc_python, flatc_runner, msgpack_python are real subprocess wrappers;
# protoc_gogofaster_stub returns binary_missing directly.
SUBPROCESS_WRAPPERS = [
    ("protoc_python", "protoc_python", "protobuf"),
    ("flatc_runner", "flatc_runner", "flatbuffer"),
    ("msgpack_python", "msgpack_python", "msgpack"),
]


@pytest.mark.parametrize("profile,module_name,format_kind", SUBPROCESS_WRAPPERS)
def test_wrapper_run_returns_dict_with_required_axes(
    profile: str, module_name: str, format_kind: str, monkeypatch
) -> None:
    """A successful binary invocation returns a dict containing each of the
    9 proto-family axes. Mock subprocess.run to return a synthetic JSON
    line that mimics the binary's expected output."""
    mod = _import_wrapper(module_name)

    sample_stdout = json.dumps(
        {
            "input_id": "PROTO-TEST-001",
            "parser_profile": profile,
            "schema_version": "v1.0",
            "format_kind": format_kind,
            "declared_schema_version": "v3",
            "message_type_name": "com.example.Message",
            "field_count": 5,
            "field_unknown_count": 0,
            "oneof_active_field": None,
            "decoded_field_summary": {"id": 123},
            "parser_warnings": [],
            "decode_outcome": {"status": "ok", "bytes_out": 64},
        }
    )

    class FakeCompleted:
        returncode = 0
        stdout = sample_stdout.encode("utf-8")
        stderr = b""

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"\x08\x96\x01", input_id="PROTO-TEST-001")
    assert isinstance(result, dict)
    for axis in (
        "format_kind",
        "declared_schema_version",
        "message_type_name",
        "field_count",
        "field_unknown_count",
        "oneof_active_field",
        "decoded_field_summary",
        "parser_warnings",
        "decode_outcome",
    ):
        assert axis in result, f"{profile} wrapper missing axis {axis!r}"
    assert result["input_id"] == "PROTO-TEST-001"
    assert result["parser_profile"] == profile


@pytest.mark.parametrize("profile,module_name,format_kind", SUBPROCESS_WRAPPERS)
def test_wrapper_binary_missing_returns_crash_envelope(
    profile: str, module_name: str, format_kind: str, monkeypatch
) -> None:
    """When the underlying binary is not on PATH, the wrapper must catch
    FileNotFoundError and return a `_crash_envelope`-equivalent fact-vector
    with binary_missing=true and decode_outcome.status=parse_error."""
    mod = _import_wrapper(module_name)

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        raise FileNotFoundError(f"No such binary on PATH: {cmd[0]}")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"\x08", input_id="PROTO-MISSING")
    assert isinstance(result, dict)
    assert result.get("binary_missing") is True, (
        f"{profile}: when binary absent, wrapper must set binary_missing=True"
    )
    assert result.get("decode_outcome", {}).get("status") == "parse_error", (
        f"{profile}: missing-binary envelope must record "
        f"decode_outcome.status=parse_error"
    )
    assert result.get("parser_profile") == profile
    assert result.get("input_id") == "PROTO-MISSING"


@pytest.mark.parametrize("profile,module_name,format_kind", SUBPROCESS_WRAPPERS)
def test_wrapper_nonzero_exit_returns_crash_envelope(
    profile: str, module_name: str, format_kind: str, monkeypatch
) -> None:
    """If the binary exits non-zero (e.g. malformed payload rejected), the
    wrapper must return a parse_error/decode_error envelope, NOT raise."""
    mod = _import_wrapper(module_name)

    class FakeCompleted:
        returncode = 1
        stdout = b""
        stderr = b"invalid wire format"

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"<BROKEN>", input_id="PROTO-BAD")
    assert result.get("decode_outcome", {}).get("status") in {
        "parse_error",
        "decode_error",
    }
    assert result.get("input_id") == "PROTO-BAD"
    assert result.get("parser_profile") == profile


# Stubs always return binary_missing — protoc_gogofaster_stub on every platform
STUB_WRAPPERS = [
    ("protoc_gogofaster_stub", "protoc_gogofaster_stub"),
]


@pytest.mark.parametrize("profile,module_name", STUB_WRAPPERS)
def test_stub_wrapper_always_returns_binary_missing_envelope(
    profile: str, module_name: str
) -> None:
    """protoc_gogofaster_stub always emits a binary_missing envelope;
    no subprocess is invoked."""
    mod = _import_wrapper(module_name)
    result = mod.run(witness_bytes=b"\x08", input_id="PROTO-STUB")
    assert isinstance(result, dict)
    assert result.get("binary_missing") is True, (
        f"{profile}: stub must always set binary_missing=True"
    )
    assert result.get("decode_outcome", {}).get("status") == "parse_error"
    assert result.get("parser_profile") == profile
    assert result.get("input_id") == "PROTO-STUB"


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_emits_schema_valid_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """The crash envelope produced by an absent binary must validate
    against schema/fact-vector-proto.schema.json."""
    mod = _import_wrapper(module_name)

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        raise FileNotFoundError(cmd[0])

    # Patch subprocess.run; the stubs will not call it but it's safe to mock.
    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"", input_id="PROTO-CONTRACT")

    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        pytest.skip("jsonschema not available")
    from aegisgraph.io import load_json, repo_root

    schema = load_json(repo_root() / "schema" / "fact-vector-proto.schema.json")
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(result), key=str)
    assert not errors, (
        f"{profile} crash envelope failed schema validation: "
        + "; ".join(
            f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors
        )
    )
