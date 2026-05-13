"""Schema-shape tests for schema/fact-vector-image.schema.json.

The image-family fact-vector schema must:

  * Be a valid JSON Schema Draft 2020-12 document.
  * Declare the 7 image-family axes per Asemarefactor.md lines 63-77:
      dimensions (object: width, height), color_space (object: profile,
      depth), alpha_premultiplied (bool), frame_count (int),
      first_pixel_rgba (object: r,g,b,a), decode_outcome (object: status,
      bytes_out), parser_warnings (array of strings).
  * Require `input_id` + `parser_profile` (the cross-family identity keys
    that the diff engine pairs vectors on).
  * Accept sample fact-vectors emitted by the image wrappers.

The schema lives alongside schema/fact-vector.schema.json (URL family)
and the proposed v2 — adding a per-family schema is an *additive*
extension per ADR-0010, not a replacement.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisgraph.io import load_json, repo_root


SCHEMA_PATH = repo_root() / "schema" / "fact-vector-image.schema.json"


def _load_schema() -> dict[str, Any]:
    assert SCHEMA_PATH.is_file(), f"missing {SCHEMA_PATH}"
    return load_json(SCHEMA_PATH)


def _validator(schema: dict[str, Any]):
    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        pytest.skip("jsonschema not available in this environment")
    return Draft202012Validator(schema)


def test_schema_file_exists() -> None:
    assert SCHEMA_PATH.is_file()


def test_schema_declares_draft_2020_12() -> None:
    schema = _load_schema()
    assert schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"


def test_schema_id_is_canonical() -> None:
    schema = _load_schema()
    sid = schema.get("$id", "")
    assert "fact-vector-image.schema.json" in sid


def test_schema_is_self_valid() -> None:
    """The schema document itself must be a valid Draft 2020-12 metaschema instance."""
    schema = _load_schema()
    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        pytest.skip("jsonschema not available")
    # check_schema raises if not metaschema-compliant.
    Draft202012Validator.check_schema(schema)


def test_required_axes_present() -> None:
    schema = _load_schema()
    required = set(schema.get("required") or [])
    # We require all 7 axes plus the identity keys input_id + parser_profile.
    must_be_required = {
        "input_id",
        "parser_profile",
        "dimensions",
        "color_space",
        "alpha_premultiplied",
        "frame_count",
        "first_pixel_rgba",
        "decode_outcome",
        "parser_warnings",
    }
    missing = must_be_required - required
    assert not missing, (
        f"fact-vector-image schema missing required fields: {sorted(missing)}"
    )


def test_sample_record_validates() -> None:
    """A well-formed image fact-vector validates against the schema."""
    schema = _load_schema()
    validator = _validator(schema)
    sample: dict[str, Any] = {
        "input_id": "IMG-001",
        "parser_profile": "libwebp",
        "schema_version": "v1.0",
        "dimensions": {"width": 1024, "height": 768},
        "color_space": {"profile": "sRGB", "depth": 8},
        "alpha_premultiplied": False,
        "frame_count": 1,
        "first_pixel_rgba": {"r": 255, "g": 0, "b": 0, "a": 255},
        "decode_outcome": {"status": "ok", "bytes_out": 1024 * 768 * 3},
        "parser_warnings": [],
    }
    errors = sorted(validator.iter_errors(sample), key=str)
    assert not errors, (
        "valid sample failed schema validation: "
        + "; ".join(f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
    )


def test_decode_outcome_status_enum_includes_crash() -> None:
    """Per Asemarefactor.md line 70, decode_outcome.status must accept
    {ok, decode_error, oom, crash} — and the disagreement triage relies on
    'crash' being a valid distinguishable value.
    """
    schema = _load_schema()
    # The status enum is nested under properties.decode_outcome.properties.status.enum.
    decode_outcome = (
        schema.get("properties", {}).get("decode_outcome", {})
    )
    status_schema = (
        decode_outcome.get("properties", {}).get("status", {})
    )
    enum_values = set(status_schema.get("enum") or [])
    required = {"ok", "decode_error", "oom", "crash"}
    assert required.issubset(enum_values), (
        f"decode_outcome.status enum must include {sorted(required)}; "
        f"got {sorted(enum_values)}"
    )


def test_binary_missing_envelope_validates() -> None:
    """Per the wrapper contract, when a native/JVM binary is absent the
    wrapper returns a `_crash_envelope`-equivalent shape with
    `binary_missing=true` and a `decode_outcome.status` of `crash`. That
    envelope must still validate so the diff engine can include it in
    triage (an absent binary surfaces as a degenerate fact-vector, not as
    a hard error).
    """
    schema = _load_schema()
    validator = _validator(schema)
    envelope: dict[str, Any] = {
        "input_id": "IMG-001",
        "parser_profile": "libheif",
        "schema_version": "v1.0",
        "binary_missing": True,
        "errors": ["libheif_dec_cli not on PATH"],
        "dimensions": None,
        "color_space": None,
        "alpha_premultiplied": None,
        "frame_count": None,
        "first_pixel_rgba": None,
        "decode_outcome": {"status": "crash", "bytes_out": 0},
        "parser_warnings": ["wrapper binary missing"],
    }
    errors = sorted(validator.iter_errors(envelope), key=str)
    assert not errors, (
        "binary_missing envelope failed validation: "
        + "; ".join(f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
    )
