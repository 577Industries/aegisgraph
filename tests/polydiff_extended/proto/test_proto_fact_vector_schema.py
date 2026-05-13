"""Schema-shape tests for schema/fact-vector-proto.schema.json.

The proto-family fact-vector schema must:

  * Be a valid JSON Schema Draft 2020-12 document.
  * Declare the 9 proto-family axes:
      format_kind (enum: protobuf|flatbuffer|msgpack),
      declared_schema_version (str|null),
      message_type_name (str|null),
      field_count (int|null),
      field_unknown_count (int|null),
      oneof_active_field (str|null),
      decoded_field_summary (object|null),
      parser_warnings (array<string>),
      decode_outcome (object: status, bytes_out).
  * Require `input_id` + `parser_profile` (cross-family identity keys).
  * Accept sample fact-vectors emitted by the proto wrappers.

Sibling of schema/fact-vector-image.schema.json,
schema/fact-vector-opengraph.schema.json,
schema/fact-vector-deeplink.schema.json, and
schema/fact-vector-qr.schema.json — additive per ADR-0010.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisgraph.io import load_json, repo_root


SCHEMA_PATH = repo_root() / "schema" / "fact-vector-proto.schema.json"


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
    assert "fact-vector-proto.schema.json" in sid


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
        "format_kind",
        "declared_schema_version",
        "message_type_name",
        "field_count",
        "field_unknown_count",
        "oneof_active_field",
        "decoded_field_summary",
        "parser_warnings",
        "decode_outcome",
    }
    missing = must_be_required - required
    assert not missing, (
        f"fact-vector-proto schema missing required fields: {sorted(missing)}"
    )


def test_sample_record_validates() -> None:
    """A well-formed proto fact-vector validates against the schema."""
    schema = _load_schema()
    validator = _validator(schema)
    sample: dict[str, Any] = {
        "input_id": "PROTO-001",
        "parser_profile": "protoc_python",
        "schema_version": "v1.0",
        "format_kind": "protobuf",
        "declared_schema_version": "v3",
        "message_type_name": "com.example.Message",
        "field_count": 5,
        "field_unknown_count": 0,
        "oneof_active_field": None,
        "decoded_field_summary": {"id": 123, "name": "x"},
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 64},
    }
    errors = sorted(validator.iter_errors(sample), key=str)
    assert not errors, (
        "valid sample failed schema validation: "
        + "; ".join(f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
    )


def test_decode_outcome_status_enum_covers_required_values() -> None:
    """decode_outcome.status must include the parser-state values used by
    the triage classifier: ok, parse_error, decode_error, schema_mismatch."""
    schema = _load_schema()
    decode_outcome = schema.get("properties", {}).get("decode_outcome", {})
    status_schema = decode_outcome.get("properties", {}).get("status", {})
    enum_values = set(status_schema.get("enum") or [])
    required = {"ok", "parse_error", "decode_error", "schema_mismatch"}
    assert required.issubset(enum_values), (
        f"decode_outcome.status enum must include {sorted(required)}; "
        f"got {sorted(enum_values)}"
    )


def test_format_kind_enum_covers_three_formats() -> None:
    """format_kind enum must cover the three canonical formats:
    protobuf, flatbuffer, msgpack."""
    schema = _load_schema()
    format_kind_schema = schema.get("properties", {}).get("format_kind", {})
    enum_values = set(format_kind_schema.get("enum") or [])
    required = {"protobuf", "flatbuffer", "msgpack"}
    assert required.issubset(enum_values), (
        f"format_kind enum must include {sorted(required)}; "
        f"got {sorted(enum_values)}"
    )


def test_binary_missing_envelope_validates() -> None:
    """The crash envelope produced when a wrapper binary is absent
    (e.g. an unavailable protoc/flatc binary, or gogofaster stub) must
    validate. Note: proto uses 'parse_error' as the missing-binary
    status — wrappers signal absence via binary_missing=true +
    parse_error.
    """
    schema = _load_schema()
    validator = _validator(schema)
    envelope: dict[str, Any] = {
        "input_id": "PROTO-MISSING",
        "parser_profile": "protoc_python",
        "schema_version": "v1.0",
        "binary_missing": True,
        "errors": ["protoc not on PATH"],
        "format_kind": "protobuf",
        "declared_schema_version": None,
        "message_type_name": None,
        "field_count": None,
        "field_unknown_count": None,
        "oneof_active_field": None,
        "decoded_field_summary": None,
        "parser_warnings": ["wrapper binary missing"],
        "decode_outcome": {"status": "parse_error", "bytes_out": 0},
    }
    errors = sorted(validator.iter_errors(envelope), key=str)
    assert not errors, (
        "binary_missing envelope failed validation: "
        + "; ".join(f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
    )
