"""Schema-shape tests for schema/fact-vector-deeplink.schema.json.

The deeplink-family fact-vector schema must:

  * Be a valid JSON Schema Draft 2020-12 document.
  * Declare the 10 deeplink-family axes:
      scheme (str), host (str|null), path (str|null),
      query_params (object|null), fragment_action (str|null),
      declared_permissions (array<string>),
      intent_action (str|null), intent_category (array<string>|null),
      parser_warnings (array<string>),
      decode_outcome (object: status, bytes_out).
  * Require `input_id` + `parser_profile` (cross-family identity keys).
  * Accept sample fact-vectors emitted by the deeplink wrappers.

Sibling of schema/fact-vector-image.schema.json and
schema/fact-vector-opengraph.schema.json — additive per ADR-0010.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisgraph.io import load_json, repo_root


SCHEMA_PATH = repo_root() / "schema" / "fact-vector-deeplink.schema.json"


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
    assert "fact-vector-deeplink.schema.json" in sid


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
    }
    missing = must_be_required - required
    assert not missing, (
        f"fact-vector-deeplink schema missing required fields: {sorted(missing)}"
    )


def test_sample_record_validates() -> None:
    """A well-formed deeplink fact-vector validates against the schema."""
    schema = _load_schema()
    validator = _validator(schema)
    sample: dict[str, Any] = {
        "input_id": "DL-001",
        "parser_profile": "android_intent_uri",
        "schema_version": "v1.0",
        "scheme": "intent",
        "host": "example.com",
        "path": "/chat/abc",
        "query_params": {"id": "1"},
        "fragment_action": "Intent;action=android.intent.action.VIEW;end",
        "declared_permissions": [],
        "intent_action": "android.intent.action.VIEW",
        "intent_category": ["android.intent.category.BROWSABLE"],
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 256},
    }
    errors = sorted(validator.iter_errors(sample), key=str)
    assert not errors, (
        "valid sample failed schema validation: "
        + "; ".join(f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
    )


def test_decode_outcome_status_enum_covers_required_values() -> None:
    """decode_outcome.status must include the parser-state values used by
    the triage classifier: ok, parse_error, scheme_unknown, malformed."""
    schema = _load_schema()
    decode_outcome = schema.get("properties", {}).get("decode_outcome", {})
    status_schema = decode_outcome.get("properties", {}).get("status", {})
    enum_values = set(status_schema.get("enum") or [])
    required = {"ok", "parse_error", "scheme_unknown", "malformed"}
    assert required.issubset(enum_values), (
        f"decode_outcome.status enum must include {sorted(required)}; "
        f"got {sorted(enum_values)}"
    )


def test_binary_missing_envelope_validates() -> None:
    """The crash envelope produced when a wrapper binary is absent
    (e.g. an unavailable native Android/iOS toolchain) must validate.
    Note: deeplink uses 'parse_error' as the missing-binary status (per
    the schema's enum), since the family's status set does not include
    'crash' — wrappers signal absence via binary_missing=true + parse_error.
    """
    schema = _load_schema()
    validator = _validator(schema)
    envelope: dict[str, Any] = {
        "input_id": "DL-MISSING",
        "parser_profile": "android_intent_uri",
        "schema_version": "v1.0",
        "binary_missing": True,
        "errors": ["android_intent_parser not on PATH"],
        "scheme": "",
        "host": None,
        "path": None,
        "query_params": None,
        "fragment_action": None,
        "declared_permissions": [],
        "intent_action": None,
        "intent_category": None,
        "parser_warnings": ["wrapper binary missing"],
        "decode_outcome": {"status": "parse_error", "bytes_out": 0},
    }
    errors = sorted(validator.iter_errors(envelope), key=str)
    assert not errors, (
        "binary_missing envelope failed validation: "
        + "; ".join(f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
    )
