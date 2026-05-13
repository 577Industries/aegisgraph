"""Schema-shape tests for schema/fact-vector-qr.schema.json.

The qr-family fact-vector schema must:

  * Be a valid JSON Schema Draft 2020-12 document.
  * Declare the 10 qr-family axes:
      detected_text (str|null), ecc_level (str|null), version (int|null),
      mode (enum|null), encoding_charset (str|null),
      structured_append_index (int|null),
      structured_append_total (int|null),
      fnc1_present (bool|null),
      parser_warnings (array<string>),
      decode_outcome (object: status, bytes_out).
  * Require `input_id` + `parser_profile` (cross-family identity keys).
  * Accept sample fact-vectors emitted by the qr wrappers.

Sibling of schema/fact-vector-image.schema.json,
schema/fact-vector-opengraph.schema.json, and
schema/fact-vector-deeplink.schema.json — additive per ADR-0010.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisgraph.io import load_json, repo_root


SCHEMA_PATH = repo_root() / "schema" / "fact-vector-qr.schema.json"


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
    assert "fact-vector-qr.schema.json" in sid


def test_schema_is_self_valid() -> None:
    schema = _load_schema()
    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        pytest.skip("jsonschema not available")
    Draft202012Validator.check_schema(schema)


def test_required_axes_present() -> None:
    schema = _load_schema()
    required = set(schema.get("required") or [])
    must_be_required = {
        "input_id",
        "parser_profile",
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
    }
    missing = must_be_required - required
    assert not missing, (
        f"fact-vector-qr schema missing required fields: {sorted(missing)}"
    )


def test_sample_record_validates() -> None:
    """A well-formed qr fact-vector validates against the schema."""
    schema = _load_schema()
    validator = _validator(schema)
    sample: dict[str, Any] = {
        "input_id": "QR-001",
        "parser_profile": "zxing_cli",
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
    errors = sorted(validator.iter_errors(sample), key=str)
    assert not errors, (
        "valid sample failed schema validation: "
        + "; ".join(f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
    )


def test_decode_outcome_status_enum_covers_required_values() -> None:
    """decode_outcome.status must include the parser-state values used by
    the triage classifier: ok, parse_error, decode_error, no_qr_found."""
    schema = _load_schema()
    decode_outcome = schema.get("properties", {}).get("decode_outcome", {})
    status_schema = decode_outcome.get("properties", {}).get("status", {})
    enum_values = set(status_schema.get("enum") or [])
    required = {"ok", "parse_error", "decode_error", "no_qr_found"}
    assert required.issubset(enum_values), (
        f"decode_outcome.status enum must include {sorted(required)}; "
        f"got {sorted(enum_values)}"
    )


def test_mode_enum_covers_qr_modes() -> None:
    """mode enum must cover the four canonical QR data modes:
    numeric, alphanumeric, byte, kanji. null is also permitted
    (binary_missing / parse_error envelopes)."""
    schema = _load_schema()
    mode_schema = schema.get("properties", {}).get("mode", {})
    # Mode is nullable; the enum lives either under "enum" directly or
    # nested under an anyOf with a string variant.
    enum_values: set[str] = set()
    if "enum" in mode_schema:
        enum_values = {v for v in mode_schema["enum"] if v is not None}
    elif "anyOf" in mode_schema:
        for variant in mode_schema["anyOf"]:
            if "enum" in variant:
                enum_values.update(v for v in variant["enum"] if v is not None)
    required = {"numeric", "alphanumeric", "byte", "kanji"}
    assert required.issubset(enum_values), (
        f"mode enum must include {sorted(required)}; got {sorted(enum_values)}"
    )


def test_binary_missing_envelope_validates() -> None:
    """The crash envelope produced when a wrapper binary is absent
    (e.g. an unavailable ZXing/ZBar binary on PATH) must validate.
    Note: qr uses 'parse_error' as the missing-binary status — wrappers
    signal absence via binary_missing=true + parse_error.
    """
    schema = _load_schema()
    validator = _validator(schema)
    envelope: dict[str, Any] = {
        "input_id": "QR-MISSING",
        "parser_profile": "zxing_cli",
        "schema_version": "v1.0",
        "binary_missing": True,
        "errors": ["zxing_cli not on PATH"],
        "detected_text": None,
        "ecc_level": None,
        "version": None,
        "mode": None,
        "encoding_charset": None,
        "structured_append_index": None,
        "structured_append_total": None,
        "fnc1_present": None,
        "parser_warnings": ["wrapper binary missing"],
        "decode_outcome": {"status": "parse_error", "bytes_out": 0},
    }
    errors = sorted(validator.iter_errors(envelope), key=str)
    assert not errors, (
        "binary_missing envelope failed validation: "
        + "; ".join(f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
    )
