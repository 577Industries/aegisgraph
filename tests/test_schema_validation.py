"""Schema-side validation tests.

Two responsibilities:

1. Round-trip: an extraction-emitted record validates against the v1.0 schema
   (existing test, preserved verbatim).
2. Self-check: every JSON Schema file under /schema/ is itself a valid
   Draft 2020-12 schema. This protects against typos that would otherwise
   surface only when an evidence record happens to exercise the broken
   subschema.

Per docs/decision-log/0010-schema-additive-only.md, schemas evolve additively;
new fields must be nullable to keep v1.0 records valid. Breaking changes
require a new versioned file (e.g. fact-vector.schema.v2.proposed.json) and
a fresh ADR. This test file is the wall.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from aegisgraph.extraction import make_media_reachability_record
from aegisgraph.io import load_json, repo_root
from aegisgraph.schema import schema_dir, validate_evidence_record


def test_extraction_record_validates_against_v1_schema() -> None:
    record = make_media_reachability_record("signal")
    assert validate_evidence_record(record, repo_root()) == []


def _schema_files() -> list[Path]:
    return sorted(schema_dir(repo_root()).glob("*.schema.json"))


@pytest.mark.parametrize(
    "schema_path",
    _schema_files(),
    ids=lambda p: p.name,
)
def test_each_schema_file_is_valid_draft_2020_12(schema_path: Path) -> None:
    schema = load_json(schema_path)
    # Raises jsonschema.exceptions.SchemaError on malformed schemas.
    Draft202012Validator.check_schema(schema)


def test_at_least_six_schemas_present() -> None:
    """Sanity-check that the schema directory hasn't been silently truncated.

    Phase 0 ships 6 schemas: evidence, fact-vector, finding, hash-chain,
    recommendation, tool-output. New schemas may be added (additive policy);
    if existing ones disappear, that is a breaking change and this test
    will fail-loud to flag the regression.
    """
    files = _schema_files()
    assert len(files) >= 6, f"expected >= 6 schema files, found {[f.name for f in files]}"
    expected = {
        "evidence.schema.json",
        "fact-vector.schema.json",
        "finding.schema.json",
        "hash-chain.schema.json",
        "recommendation.schema.json",
        "tool-output.schema.json",
    }
    present = {f.name for f in files}
    missing = expected - present
    assert not missing, f"baseline schema(s) missing: {sorted(missing)}"
