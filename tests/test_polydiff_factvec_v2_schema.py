"""Validate sample fact-vectors against the proposed v2 schema."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "polydiff" / "factvec" / "schema_v2.json"
PROPOSED_PATH = REPO_ROOT / "schema" / "fact-vector.schema.v2.proposed.json"


def test_v2_schema_files_exist():
    assert SCHEMA_PATH.exists(), f"missing {SCHEMA_PATH}"
    assert PROPOSED_PATH.exists(), f"missing {PROPOSED_PATH}"


def test_proposed_schema_matches_module_schema():
    """The schema in polydiff/factvec/ must match the proposal in schema/."""
    with SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        a = json.load(fh)
    with PROPOSED_PATH.open("r", encoding="utf-8") as fh:
        b = json.load(fh)
    # Required fields must be identical.
    assert a["required"] == b["required"]
    # Property keys must be identical.
    assert set(a["properties"].keys()) == set(b["properties"].keys())


def test_v1_required_fields_remain_required_in_v2():
    """Backwards compat: every v1 required field must still be required in v2."""
    v1_required = [
        "input_id", "parser_profile", "scheme", "host", "port", "path",
        "userinfo_present", "host_is_private_or_link_local", "parse_error",
    ]
    with SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        v2 = json.load(fh)
    for field in v1_required:
        assert field in v2["required"], f"v2 dropped required v1 field: {field}"


@pytest.mark.parametrize("url,case_id", [
    ("https://example.com/", "TEST-001"),
    ("http://0177.0.0.1/", "TEST-002"),
    ("https://example.com/foo/../bar", "TEST-003"),
])
def test_python_urllib_wrapper_emits_v2(url: str, case_id: str):
    """The python_urllib wrapper output validates against the v2 schema."""
    wrapper = REPO_ROOT / "polydiff" / "parsers" / "python_urllib" / "wrapper.py"
    proc = subprocess.run(
        [sys.executable, str(wrapper), "--input-id", case_id],
        input=url.encode("utf-8"),
        capture_output=True,
        timeout=10,
        check=True,
    )
    fv = json.loads(proc.stdout.decode("utf-8").strip())

    # Try jsonschema first (preferred), fall back to structural check.
    try:
        import jsonschema  # type: ignore[import-untyped]
        with SCHEMA_PATH.open("r", encoding="utf-8") as fh:
            schema = json.load(fh)
        validator = jsonschema.Draft202012Validator(schema)
        errors = list(validator.iter_errors(fv))
        assert not errors, f"v2 schema errors: {[e.message for e in errors]}"
    except ImportError:
        # Structural fallback
        for k in ("input_id", "parser_profile", "parsed", "errors", "warnings"):
            assert k in fv, f"missing required key {k!r}"
        assert isinstance(fv["errors"], list)
        assert isinstance(fv["warnings"], list)
        assert isinstance(fv["parsed"], bool)


def test_normalize_fills_missing_axes():
    """polydiff.factvec.normalize must fill missing axes with null + warnings."""
    from polydiff.factvec.normalize import normalize, V2_REQUIRED_KEYS, ALL_V2_KEYS

    minimal = {
        "input_id": "X",
        "parser_profile": "fake",
        "parsed": True,
        "errors": [],
        "warnings": [],
        "scheme": "https",
        "host": "example.com",
        "port": None,
        "path": "/",
        "userinfo_present": False,
        "host_is_private_or_link_local": False,
        "parse_error": None,
    }
    out = normalize(minimal)
    for k in ALL_V2_KEYS:
        assert k in out, f"normalize missed {k}"
    # Optional axes get null + warning.
    for k in ("host_punycode", "tab_or_newline_stripped"):
        assert out[k] is None
    # Warnings include the "not directly observable" entries.
    assert any("not directly observable" in w for w in out["warnings"])
