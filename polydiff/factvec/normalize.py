"""Normalize parser-native output into the canonical v2 fact-vector envelope.

Each subprocess wrapper is supposed to emit a v2-compliant envelope on
stdout. In practice, language-runtime quirks (JSON boolean/null
serialization, missing optional axes, parsers that simply do not expose
a feature) mean the orchestrator needs a centralized normalization
stage that:

  1. Fills missing v2 axes with `null` and appends an explanatory
     warning of the form "axis 'X' not directly observable by parser
     'Y'".
  2. Coerces v1 fact-vector inputs (legacy shape) into v2 by adding
     `parsed`, `errors[]`, `warnings[]`, and ensuring every required
     v2 key exists.
  3. Validates the resulting envelope against the v2 JSON Schema (when
     `jsonschema` is installed), so that downstream consumers can
     trust the envelope shape.

This module is import-free with respect to any parser library — only
stdlib + (optional) jsonschema. Importing a parser at orchestrator
scope would defeat the subprocess isolation contract described in
polydiff/parsers/README.md.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

# All axes the v2 schema knows about. Kept in alphabetical order by axis
# name within their groups so future additions are easy to spot.
V2_REQUIRED_KEYS: tuple[str, ...] = (
    "input_id",
    "parser_profile",
    "parsed",
    "errors",
    "warnings",
    "scheme",
    "host",
    "port",
    "path",
    "userinfo_present",
    "host_is_private_or_link_local",
    "parse_error",
)

V2_OPTIONAL_KEYS: tuple[str, ...] = (
    "schema_version",
    "scheme_lowercased",
    "userinfo_raw",
    "username",
    "password_present",
    "host_raw",
    "host_lowercased",
    "host_decoded",
    "host_is_ip_literal",
    "host_is_ipv4",
    "host_is_ipv6",
    "host_is_ipvFuture",
    "host_is_loopback",
    "host_has_idn",
    "host_punycode",
    "port_present",
    "port_value",
    "port_default_inferred",
    "path_raw",
    "path_normalized",
    "path_traversal_resolved",
    "query_raw",
    "query_pairs",
    "fragment_raw",
    "percent_decoding_applied_in_host",
    "percent_decoding_applied_in_path",
    "trailing_slash_normalized",
    "leading_zeroes_in_octets_stripped",
    "tab_or_newline_stripped",
    "backslash_treated_as_slash",
    "control_chars_in_host_rejected",
    "scheme_authority_separator_strict",
    "raw_serialized",
)

ALL_V2_KEYS: tuple[str, ...] = V2_REQUIRED_KEYS + V2_OPTIONAL_KEYS

_DEFAULTS: dict[str, Any] = {
    "schema_version": "v2",
    "parsed": False,
    "errors": [],
    "warnings": [],
    "userinfo_present": False,
    "host_is_private_or_link_local": False,
}


def schema_v2_path() -> Path:
    """Return path to the canonical v2 schema file."""
    return Path(__file__).resolve().parent / "schema_v2.json"


def load_schema_v2() -> dict[str, Any]:
    """Read polydiff/factvec/schema_v2.json from disk."""
    with schema_v2_path().open("r", encoding="utf-8") as fh:
        return json.load(fh)


def normalize(envelope: dict[str, Any], parser_profile: str | None = None) -> dict[str, Any]:
    """Coerce `envelope` into a v2-compliant envelope.

    - Adds `schema_version="v2"` if absent.
    - Adds any missing required key with a sensible default.
    - Fills missing optional keys with None and appends a warning.
    - Forces `errors`/`warnings` to be lists of strings.
    - Ensures `parser_profile` is set (falling back to caller-provided
      `parser_profile` if not in the envelope).
    """
    out = copy.deepcopy(envelope)
    out.setdefault("schema_version", "v2")

    if parser_profile and not out.get("parser_profile"):
        out["parser_profile"] = parser_profile

    for k, default in _DEFAULTS.items():
        if k not in out:
            out[k] = copy.deepcopy(default)

    out.setdefault("errors", [])
    out.setdefault("warnings", [])
    if not isinstance(out["errors"], list):
        out["errors"] = [str(out["errors"])]
    if not isinstance(out["warnings"], list):
        out["warnings"] = [str(out["warnings"])]

    profile = out.get("parser_profile", "unknown")
    for k in ALL_V2_KEYS:
        if k not in out:
            out[k] = None
            out["warnings"].append(f"axis {k!r} not directly observable by parser {profile!r}")

    # Mirror legacy v1 fields for backwards-compat consumers:
    # the v1 schema requires `parse_error`, `scheme`, `host`, `port`,
    # `path`. v2-emitting wrappers usually report parse_error=null and
    # carry diagnostics in `errors[]` instead — that's still v1-valid.
    if out.get("parse_error") is None and out.get("errors"):
        # Only mirror if v2 is empty; we don't want to clobber an
        # explicit non-null parse_error.
        pass

    return out


def validate(envelope: dict[str, Any]) -> list[str]:
    """Validate against the v2 JSON Schema. Returns list of error strings.

    If `jsonschema` is not importable, falls back to a structural check
    over `V2_REQUIRED_KEYS`.
    """
    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        return _structural_validate(envelope)

    schema = load_schema_v2()
    validator = jsonschema.Draft202012Validator(schema)
    return [error.message for error in validator.iter_errors(envelope)]


def _structural_validate(envelope: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for k in V2_REQUIRED_KEYS:
        if k not in envelope:
            errors.append(f"missing required key {k!r}")
    if "errors" in envelope and not isinstance(envelope["errors"], list):
        errors.append("'errors' must be a list")
    if "warnings" in envelope and not isinstance(envelope["warnings"], list):
        errors.append("'warnings' must be a list")
    if "parsed" in envelope and not isinstance(envelope["parsed"], bool):
        errors.append("'parsed' must be a bool")
    return errors


__all__ = [
    "ALL_V2_KEYS",
    "V2_REQUIRED_KEYS",
    "V2_OPTIONAL_KEYS",
    "load_schema_v2",
    "normalize",
    "schema_v2_path",
    "validate",
]
