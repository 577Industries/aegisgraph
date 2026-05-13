"""Schema-shape tests for schema/fact-vector-opengraph.schema.json.

The opengraph-family fact-vector schema must:

  * Be a valid JSON Schema Draft 2020-12 document.
  * Declare the 11 opengraph-family axes:
      og_title (str|null), og_image (str|null), og_type (str|null),
      og_url (str|null), og_video (str|null), twitter_card_type (str|null),
      twitter_image (str|null), oembed_type (str|null),
      canonical_url (str|null), parser_warnings (array<string>),
      decode_outcome (object: status, bytes_out).
  * Require `input_id` + `parser_profile` (cross-family identity keys).
  * Accept sample fact-vectors emitted by the opengraph wrappers.

Sibling of schema/fact-vector-image.schema.json — additive per ADR-0010.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisgraph.io import load_json, repo_root


SCHEMA_PATH = repo_root() / "schema" / "fact-vector-opengraph.schema.json"


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
    assert "fact-vector-opengraph.schema.json" in sid


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
    }
    missing = must_be_required - required
    assert not missing, (
        f"fact-vector-opengraph schema missing required fields: {sorted(missing)}"
    )


def test_sample_record_validates() -> None:
    """A well-formed opengraph fact-vector validates against the schema."""
    schema = _load_schema()
    validator = _validator(schema)
    sample: dict[str, Any] = {
        "input_id": "OG-001",
        "parser_profile": "facebook_og",
        "schema_version": "v1.0",
        "og_title": "Example Article",
        "og_image": "https://example.com/cover.png",
        "og_type": "article",
        "og_url": "https://example.com/articles/1",
        "og_video": None,
        "twitter_card_type": "summary_large_image",
        "twitter_image": "https://example.com/cover.png",
        "oembed_type": None,
        "canonical_url": "https://example.com/articles/1",
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 1024},
    }
    errors = sorted(validator.iter_errors(sample), key=str)
    assert not errors, (
        "valid sample failed schema validation: "
        + "; ".join(f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
    )


def test_decode_outcome_status_enum_includes_crash() -> None:
    """decode_outcome.status must accept {ok, decode_error, oom, crash} —
    the triage classifier relies on 'crash' as a first-class value."""
    schema = _load_schema()
    decode_outcome = schema.get("properties", {}).get("decode_outcome", {})
    status_schema = decode_outcome.get("properties", {}).get("status", {})
    enum_values = set(status_schema.get("enum") or [])
    required = {"ok", "decode_error", "oom", "crash"}
    assert required.issubset(enum_values), (
        f"decode_outcome.status enum must include {sorted(required)}; "
        f"got {sorted(enum_values)}"
    )


def test_binary_missing_envelope_validates() -> None:
    """The crash envelope produced when a wrapper binary is absent
    (e.g. an unavailable Python OG parser package) must validate."""
    schema = _load_schema()
    validator = _validator(schema)
    envelope: dict[str, Any] = {
        "input_id": "OG-MISSING",
        "parser_profile": "facebook_og",
        "schema_version": "v1.0",
        "binary_missing": True,
        "errors": ["facebook_og_parser not on PATH"],
        "og_title": None,
        "og_image": None,
        "og_type": None,
        "og_url": None,
        "og_video": None,
        "twitter_card_type": None,
        "twitter_image": None,
        "oembed_type": None,
        "canonical_url": None,
        "parser_warnings": ["wrapper binary missing"],
        "decode_outcome": {"status": "crash", "bytes_out": 0},
    }
    errors = sorted(validator.iter_errors(envelope), key=str)
    assert not errors, (
        "binary_missing envelope failed validation: "
        + "; ".join(f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors)
    )
