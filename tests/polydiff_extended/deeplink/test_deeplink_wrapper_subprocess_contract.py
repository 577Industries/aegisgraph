"""Wrapper-subprocess contract tests for the deeplink family.

Each deeplink wrapper (android_intent_uri, ios_universal_link,
web_url_fallback, custom_scheme_parser) is a subprocess that:

  * Reads the witness deeplink URI bytes from stdin.
  * Writes a single JSON line to stdout matching
    schema/fact-vector-deeplink.schema.json.
  * Exits 0 on success; non-zero exits are converted to a
    `_crash_envelope`-equivalent fact-vector with
    decode_outcome.status=parse_error and
    parser_warnings=["wrapper crash recorded as a Finding"].

When the underlying parser package/binary is NOT available (no Android /
iOS toolchain in the devcontainer is the expected case), the wrapper
returns a degenerate fact-vector with binary_missing=true and
decode_outcome.status=parse_error. Tests mock subprocess.run so they
exercise wrapper logic without requiring any installed parsers.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest


from aegisgraph.polydiff.families.deeplink.wrappers import (
    android_intent_uri,
    custom_scheme_parser,
    ios_universal_link,
    web_url_fallback,
)


WRAPPER_MODULES = {
    "android_intent_uri": android_intent_uri,
    "ios_universal_link": ios_universal_link,
    "web_url_fallback": web_url_fallback,
    "custom_scheme_parser": custom_scheme_parser,
}

WRAPPERS = [
    ("android_intent_uri", "android_intent_uri"),
    ("ios_universal_link", "ios_universal_link"),
    ("web_url_fallback", "web_url_fallback"),
    ("custom_scheme_parser", "custom_scheme_parser"),
]


def _import_wrapper(module_name: str):
    if module_name not in WRAPPER_MODULES:
        raise KeyError(
            f"unknown deeplink wrapper module {module_name!r}; "
            f"expected one of {sorted(WRAPPER_MODULES)}"
        )
    return WRAPPER_MODULES[module_name]


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_module_importable(profile: str, module_name: str) -> None:
    mod = _import_wrapper(module_name)
    assert hasattr(mod, "run"), (
        f"deeplink wrapper {module_name} must expose a `run(witness_bytes, "
        f"input_id) -> dict` callable"
    )


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_run_returns_dict_with_required_axes(
    profile: str, module_name: str, monkeypatch
) -> None:
    """A successful binary invocation returns a dict containing each of the
    10 deeplink-family axes. Mock subprocess.run to return a synthetic
    JSON line that mimics the binary's expected output."""
    mod = _import_wrapper(module_name)

    sample_stdout = json.dumps(
        {
            "input_id": "DL-TEST-001",
            "parser_profile": profile,
            "schema_version": "v1.0",
            "scheme": "https",
            "host": "e.example",
            "path": "/chat/abc",
            "query_params": {"k": "v"},
            "fragment_action": None,
            "declared_permissions": [],
            "intent_action": None,
            "intent_category": None,
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
    result = mod.run(witness_bytes=b"https://e.example/chat/abc?k=v", input_id="DL-TEST-001")
    assert isinstance(result, dict)
    for axis in (
        "scheme",
        "host",
        "path",
        "query_params",
        "fragment_action",
        "declared_permissions",
        "intent_action",
        "intent_category",
        "parser_warnings",
        "decode_outcome",
    ):
        assert axis in result, f"{profile} wrapper missing axis {axis!r}"
    assert result["input_id"] == "DL-TEST-001"
    assert result["parser_profile"] == profile


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
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
    result = mod.run(witness_bytes=b"intent://foo", input_id="DL-MISSING")
    assert isinstance(result, dict)
    assert result.get("binary_missing") is True, (
        f"{profile}: when binary absent, wrapper must set binary_missing=True"
    )
    assert result.get("decode_outcome", {}).get("status") == "parse_error", (
        f"{profile}: missing-binary envelope must record "
        f"decode_outcome.status=parse_error"
    )
    assert result.get("parser_profile") == profile
    assert result.get("input_id") == "DL-MISSING"


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_nonzero_exit_returns_crash_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """If the binary exits non-zero (e.g. malformed input rejected), the
    wrapper must return a parse_error/malformed envelope, NOT raise."""
    mod = _import_wrapper(module_name)

    class FakeCompleted:
        returncode = 1
        stdout = b""
        stderr = b"invalid deeplink input"

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"<BROKEN>", input_id="DL-BAD")
    assert result.get("decode_outcome", {}).get("status") in {
        "parse_error",
        "malformed",
    }
    assert result.get("input_id") == "DL-BAD"
    assert result.get("parser_profile") == profile


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_emits_schema_valid_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """The crash envelope produced by an absent binary must validate
    against schema/fact-vector-deeplink.schema.json."""
    mod = _import_wrapper(module_name)

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"", input_id="DL-CONTRACT")

    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        pytest.skip("jsonschema not available")
    from aegisgraph.io import load_json, repo_root

    schema = load_json(repo_root() / "schema" / "fact-vector-deeplink.schema.json")
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(result), key=str)
    assert not errors, (
        f"{profile} crash envelope failed schema validation: "
        + "; ".join(
            f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors
        )
    )
