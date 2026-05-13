"""Wrapper-subprocess contract tests for the opengraph family.

Each opengraph wrapper (facebook_og, twitter_card, oembed,
beautifulsoup_fallback) is a subprocess that:

  * Reads the witness HTML/JSON bytes from stdin.
  * Writes a single JSON line to stdout matching
    schema/fact-vector-opengraph.schema.json.
  * Exits 0 on success; non-zero exits are converted to a
    `_crash_envelope`-equivalent fact-vector with
    decode_outcome.status=crash and
    parser_warnings=["wrapper crash recorded as a Finding"].

When the underlying parser package/binary is NOT available, the wrapper
returns a degenerate fact-vector with binary_missing=true and
decode_outcome.status=crash. Tests mock subprocess.run so they exercise
wrapper logic without requiring any installed parsers.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest


from aegisgraph.polydiff.families.opengraph.wrappers import (
    beautifulsoup_fallback,
    facebook_og,
    oembed,
    twitter_card,
)


WRAPPER_MODULES = {
    "facebook_og": facebook_og,
    "twitter_card": twitter_card,
    "oembed": oembed,
    "beautifulsoup_fallback": beautifulsoup_fallback,
}

WRAPPERS = [
    ("facebook_og", "facebook_og"),
    ("twitter_card", "twitter_card"),
    ("oembed", "oembed"),
    ("beautifulsoup_fallback", "beautifulsoup_fallback"),
]


def _import_wrapper(module_name: str):
    if module_name not in WRAPPER_MODULES:
        raise KeyError(
            f"unknown opengraph wrapper module {module_name!r}; "
            f"expected one of {sorted(WRAPPER_MODULES)}"
        )
    return WRAPPER_MODULES[module_name]


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_module_importable(profile: str, module_name: str) -> None:
    mod = _import_wrapper(module_name)
    assert hasattr(mod, "run"), (
        f"opengraph wrapper {module_name} must expose a `run(witness_bytes, "
        f"input_id) -> dict` callable"
    )


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_run_returns_dict_with_required_axes(
    profile: str, module_name: str, monkeypatch
) -> None:
    """A successful binary invocation returns a dict containing each of the
    11 opengraph-family axes. Mock subprocess.run to return a synthetic
    JSON line that mimics the binary's expected output."""
    mod = _import_wrapper(module_name)

    sample_stdout = json.dumps(
        {
            "input_id": "OG-TEST-001",
            "parser_profile": profile,
            "schema_version": "v1.0",
            "og_title": "Test",
            "og_image": "https://e.example/cover.png",
            "og_type": "article",
            "og_url": "https://e.example/a",
            "og_video": None,
            "twitter_card_type": "summary",
            "twitter_image": "https://e.example/cover.png",
            "oembed_type": None,
            "canonical_url": "https://e.example/a",
            "parser_warnings": [],
            "decode_outcome": {"status": "ok", "bytes_out": 256},
        }
    )

    class FakeCompleted:
        returncode = 0
        stdout = sample_stdout.encode("utf-8")
        stderr = b""

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"<html></html>", input_id="OG-TEST-001")
    assert isinstance(result, dict)
    for axis in (
        "og_title",
        "og_image",
        "og_type",
        "og_url",
        "og_video",
        "twitter_card_type",
        "twitter_image",
        "oembed_type",
        "canonical_url",
        "parser_warnings",
        "decode_outcome",
    ):
        assert axis in result, f"{profile} wrapper missing axis {axis!r}"
    assert result["input_id"] == "OG-TEST-001"
    assert result["parser_profile"] == profile


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_binary_missing_returns_crash_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """When the underlying binary is not on PATH, the wrapper must catch
    FileNotFoundError and return a `_crash_envelope`-equivalent fact-vector
    with binary_missing=true and decode_outcome.status=crash."""
    mod = _import_wrapper(module_name)

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        raise FileNotFoundError(f"No such binary on PATH: {cmd[0]}")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"<html></html>", input_id="OG-MISSING")
    assert isinstance(result, dict)
    assert result.get("binary_missing") is True, (
        f"{profile}: when binary absent, wrapper must set binary_missing=True"
    )
    assert result.get("decode_outcome", {}).get("status") == "crash", (
        f"{profile}: missing-binary envelope must record decode_outcome.status=crash"
    )
    assert result.get("parser_profile") == profile
    assert result.get("input_id") == "OG-MISSING"


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_nonzero_exit_returns_crash_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """If the binary exits non-zero (e.g. malformed input rejected), the
    wrapper must return a crash/decode_error envelope, NOT raise."""
    mod = _import_wrapper(module_name)

    class FakeCompleted:
        returncode = 1
        stdout = b""
        stderr = b"invalid html / json input"

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"<BROKEN>", input_id="OG-BAD")
    assert result.get("decode_outcome", {}).get("status") in {"decode_error", "crash"}
    assert result.get("input_id") == "OG-BAD"
    assert result.get("parser_profile") == profile


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_emits_schema_valid_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """The crash envelope produced by an absent binary must validate
    against schema/fact-vector-opengraph.schema.json."""
    mod = _import_wrapper(module_name)

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"", input_id="OG-CONTRACT")

    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        pytest.skip("jsonschema not available")
    from aegisgraph.io import load_json, repo_root

    schema = load_json(repo_root() / "schema" / "fact-vector-opengraph.schema.json")
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(result), key=str)
    assert not errors, (
        f"{profile} crash envelope failed schema validation: "
        + "; ".join(
            f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors
        )
    )
