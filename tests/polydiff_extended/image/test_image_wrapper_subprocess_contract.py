"""Wrapper-subprocess contract tests.

Each image-family wrapper (libwebp, libavif, libheif, glide_bitmap,
coil_decoder) is a subprocess that:

  * Reads the witness bytes from stdin (or `--input` file).
  * Writes a single JSON line to stdout matching
    schema/fact-vector-image.schema.json.
  * Exits 0 on success; non-zero exits are converted to a
    `_crash_envelope`-equivalent fact-vector with `decode_outcome.status =
    crash` and `parser_warnings = ["wrapper crash recorded as a Finding"]`.

When the underlying binary (libwebp_dec_cli / libavif_dec_cli /
libheif_dec_cli) is NOT on PATH, the wrapper MUST NOT raise — it must
return a degenerate fact-vector with `binary_missing=true` and
`decode_outcome.status = crash`. This lets the orchestrator include the
absent wrapper in the diff engine's output so the missing parser is
auditable (and tests run green in CI without those binaries installed).

These tests mock `subprocess.run` so they exercise the wrapper logic
without requiring any binaries.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest


# The five image-family wrappers; each is importable from
# aegisgraph.polydiff.families.image.wrappers. Modules are explicitly
# imported here (no dynamic import_module) so the whitelist is the import
# statement itself — no untrusted strings ever reach importlib.
from aegisgraph.polydiff.families.image.wrappers import (
    coil_decoder_runner,
    glide_bitmap_runner,
    libavif_cli,
    libheif_cli,
    libwebp_cli,
)

WRAPPER_MODULES = {
    "libwebp_cli": libwebp_cli,
    "libavif_cli": libavif_cli,
    "libheif_cli": libheif_cli,
    "glide_bitmap_runner": glide_bitmap_runner,
    "coil_decoder_runner": coil_decoder_runner,
}

WRAPPERS = [
    ("libwebp", "libwebp_cli"),
    ("libavif", "libavif_cli"),
    ("libheif", "libheif_cli"),
    ("glide_bitmap", "glide_bitmap_runner"),
    ("coil_decoder", "coil_decoder_runner"),
]


def _import_wrapper(module_name: str):
    """Look up a wrapper module from the explicit whitelist.

    `module_name` is a test-controlled key into a static dict — no string
    flows into importlib at runtime; the imports above bind the modules
    once at test-collection time.
    """
    if module_name not in WRAPPER_MODULES:
        raise KeyError(
            f"unknown image wrapper module {module_name!r}; "
            f"expected one of {sorted(WRAPPER_MODULES)}"
        )
    return WRAPPER_MODULES[module_name]


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_module_importable(profile: str, module_name: str) -> None:
    mod = _import_wrapper(module_name)
    assert hasattr(mod, "run"), (
        f"image wrapper module {module_name} must expose a `run(witness_bytes, "
        f"input_id) -> dict` callable"
    )


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_run_returns_dict_with_required_axes(
    profile: str, module_name: str, monkeypatch
) -> None:
    """A successful binary invocation returns a dict containing each of the
    7 image-family axes. Mock subprocess.run to return a synthetic JSON
    line that mimics the binary's expected output."""
    mod = _import_wrapper(module_name)

    sample_stdout = json.dumps(
        {
            "input_id": "IMG-TEST-001",
            "parser_profile": profile,
            "schema_version": "v1.0",
            "dimensions": {"width": 4, "height": 4},
            "color_space": {"profile": "sRGB", "depth": 8},
            "alpha_premultiplied": False,
            "frame_count": 1,
            "first_pixel_rgba": {"r": 1, "g": 2, "b": 3, "a": 255},
            "decode_outcome": {"status": "ok", "bytes_out": 48},
            "parser_warnings": [],
        }
    )

    class FakeCompleted:
        returncode = 0
        stdout = sample_stdout.encode("utf-8")
        stderr = b""

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"\x00\x01\x02", input_id="IMG-TEST-001")
    assert isinstance(result, dict)
    for axis in (
        "dimensions",
        "color_space",
        "alpha_premultiplied",
        "frame_count",
        "first_pixel_rgba",
        "decode_outcome",
        "parser_warnings",
    ):
        assert axis in result, f"{profile} wrapper missing axis {axis!r}"
    assert result["input_id"] == "IMG-TEST-001"
    assert result["parser_profile"] == profile


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_binary_missing_returns_crash_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """When the underlying binary is not on PATH, subprocess.run raises
    FileNotFoundError. The wrapper must catch this and return a
    `_crash_envelope`-equivalent fact-vector with `binary_missing=true`
    and `decode_outcome.status = crash`."""
    mod = _import_wrapper(module_name)

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        raise FileNotFoundError(f"No such binary on PATH: {cmd[0]}")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"\x00", input_id="IMG-MISSING")
    assert isinstance(result, dict)
    assert result.get("binary_missing") is True, (
        f"{profile}: when binary absent, wrapper must set binary_missing=True"
    )
    assert result.get("decode_outcome", {}).get("status") == "crash", (
        f"{profile}: missing-binary envelope must record decode_outcome.status=crash"
    )
    assert result.get("parser_profile") == profile
    assert result.get("input_id") == "IMG-MISSING"


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_nonzero_exit_returns_crash_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """If the binary exits non-zero (e.g. malformed input rejected), the
    wrapper must return a crash envelope, NOT raise."""
    mod = _import_wrapper(module_name)

    class FakeCompleted:
        returncode = 1
        stdout = b""
        stderr = b"invalid webp header"

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"NOTWEBP", input_id="IMG-BAD")
    assert result.get("decode_outcome", {}).get("status") in {"decode_error", "crash"}
    assert result.get("input_id") == "IMG-BAD"
    assert result.get("parser_profile") == profile


@pytest.mark.parametrize("profile,module_name", WRAPPERS)
def test_wrapper_emits_schema_valid_envelope(
    profile: str, module_name: str, monkeypatch
) -> None:
    """The crash envelope produced by an absent binary must validate
    against schema/fact-vector-image.schema.json."""
    mod = _import_wrapper(module_name)

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = mod.run(witness_bytes=b"", input_id="IMG-CONTRACT")

    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        pytest.skip("jsonschema not available")
    from aegisgraph.io import load_json, repo_root

    schema = load_json(repo_root() / "schema" / "fact-vector-image.schema.json")
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(result), key=str)
    assert not errors, (
        f"{profile} crash envelope failed schema validation: "
        + "; ".join(
            f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors
        )
    )
