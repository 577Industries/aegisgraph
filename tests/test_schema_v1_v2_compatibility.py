"""ADR-0013 v1↔v2 schema compatibility regression test.

Schema v2 (introduced by ADR-0013 as additive extensions to the v1.0
discovery graph: new node_type/claim_state enum values, new optional
score-vector dimensions, new optional top-level fields, plus 6 new
sibling schema files) MUST NOT invalidate any v1 evidence record that
v0.3 emitted. ADR-0010 mandates additive-only schema evolution and
makes this regression test the wall against accidental tightening.

What this test asserts:

1. Every JSON evidence-shaped record currently committed under
   extraction/output/, reprochain/evidence/, polydiff/evidence/, and
   exports/ that conforms to evidence.schema.json continues to validate
   under the schema as it exists now (v2 additions applied).
2. The hash chain of those records is recomputed and matches the
   stored record_hash byte-for-byte — proving that no field has been
   silently re-shaped (which would cascade through downstream
   validators and break public-export gate).
3. The six new node_type enum values are accepted by the schema.
4. The two new claim_state enum values are accepted by the schema.
5. The two new optional score_vector dimensions are accepted.

This is load-bearing: the v0.3 public release tarball (SHA
3ce05fbf...) hashes records produced under v1.0. If any v1 record
fails to validate or its hash drifts, ADR-0010 is breached and the
v0.3 tarball can no longer be reproduced from sources.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisgraph.hashchain import verify_hash_chain
from aegisgraph.io import load_json, repo_root
from aegisgraph.schema import validate_evidence_record


def _evidence_files_glob() -> list[Path]:
    """Collect every JSON file that looks like an emitted v1 evidence
    record (or a list/document containing them). Globs match
    aegisgraph.validation.evidence_documents()."""
    root = repo_root()
    patterns = (
        "extraction/output/**/*.json",
        "reprochain/evidence/**/*.json",
        "polydiff/evidence/**/*.json",
        "exports/private-submission/**/*.json",
        "exports/public-sanitized/**/*.json",
    )
    files: list[Path] = []
    for pattern in patterns:
        files.extend(root.glob(pattern))
    return sorted(files)


def _records_from_document(document: object) -> list[dict]:
    """Mirror aegisgraph.validation._records_from_document() — yield
    each evidence-shaped record from a document (single record, list,
    or dict with 'records' key)."""
    if isinstance(document, list):
        return [r for r in document if isinstance(r, dict)]
    if isinstance(document, dict):
        if "records" in document and isinstance(document["records"], list):
            return [r for r in document["records"] if isinstance(r, dict)]
        # treat as single record
        return [document]
    return []


def _v1_evidence_records() -> list[tuple[Path, dict]]:
    """Return (path, record) tuples for every record-shaped object that
    has the v1 evidence-record signature (id starting with AG-EV- and
    a version field == 'v1.0')."""
    pairs: list[tuple[Path, dict]] = []
    for path in _evidence_files_glob():
        try:
            doc = load_json(path)
        except Exception:
            continue
        for record in _records_from_document(doc):
            rec_id = record.get("id", "")
            version = record.get("version", "")
            if isinstance(rec_id, str) and rec_id.startswith("AG-EV-") and version == "v1.0":
                pairs.append((path, record))
    return pairs


_v1_pairs = _v1_evidence_records()


@pytest.mark.skipif(not _v1_pairs, reason="no v1 evidence records to validate against v2 schema")
@pytest.mark.parametrize(
    "path,record",
    _v1_pairs,
    ids=lambda x: x.name if isinstance(x, Path) else x.get("id", "<rec>") if isinstance(x, dict) else "<?>",
)
def test_v1_record_revalidates_under_v2_schema(path: Path, record: dict) -> None:
    """Every previously-emitted v1 record must validate against the
    schema as it exists today (with v2 additive extensions applied)."""
    errors = validate_evidence_record(record, repo_root())
    assert errors == [], f"v1 record {record['id']} from {path} fails v2 schema: {errors}"


@pytest.mark.skipif(not _v1_pairs, reason="no v1 evidence records to verify hash on")
@pytest.mark.parametrize(
    "path,record",
    _v1_pairs,
    ids=lambda x: x.name if isinstance(x, Path) else x.get("id", "<rec>") if isinstance(x, dict) else "<?>",
)
def test_v1_record_hash_chain_remains_byte_stable(path: Path, record: dict) -> None:
    """Recomputing the hash of every v1 record must match the stored
    record_hash. This catches any accidental schema change that
    serializes differently or any code change to the canonicalization
    rule."""
    if "hash_chain" not in record:
        pytest.skip(f"{record.get('id')} has no hash_chain block")
    chain = record["hash_chain"]
    if chain.get("canonicalization") != "json-v1-sorted-no-hash-chain":
        pytest.skip(f"{record.get('id')} uses different canonicalization")
    errors = verify_hash_chain(record)
    assert errors == [], (
        f"hash chain of v1 record {record.get('id')} from {path} no longer "
        f"verifies — ADR-0010 additive-only policy may have been breached, "
        f"or canonicalization changed: {errors}"
    )


def test_schema_v2_accepts_new_claim_states() -> None:
    """The v2 additive extension MUST accept the two new disclosure
    claim states (reviewed_embargoed, disclosed_public) in addition to
    the v1 states."""
    schema_path = repo_root() / "schema" / "evidence.schema.json"
    schema = load_json(schema_path)
    claim_state_enum = schema["properties"]["claim_state"]["enum"]
    assert "reviewed_embargoed" in claim_state_enum
    assert "disclosed_public" in claim_state_enum
    # And every v1 state remains present (no tightening).
    for v1_state in (
        "observed",
        "anchored",
        "scored",
        "validation_tasked",
        "reviewed",
        "accepted",
        "limited",
        "retired",
    ):
        assert v1_state in claim_state_enum, f"v1 claim state {v1_state!r} missing from v2 schema"


def test_schema_v2_accepts_new_node_types() -> None:
    """All six new discovery-graph node types must appear in the
    v2-extended node_type enum, and all v1 node types must remain."""
    schema_path = repo_root() / "schema" / "evidence.schema.json"
    schema = load_json(schema_path)
    node_type_enum = schema["$defs"]["node"]["properties"]["node_type"]["enum"]
    for new_type in (
        "discovery_run",
        "crash",
        "disagreement",
        "invariant_violation",
        "cross_target_candidate",
        "disclosure_event",
    ):
        assert new_type in node_type_enum, f"v2 node type {new_type!r} missing"
    for v1_type in (
        "entry_point",
        "handler",
        "parser",
        "decoder",
        "native_boundary",
        "sink",
        "control",
        "validation_task",
        "parser_profile",
        "fact_vector",
    ):
        assert v1_type in node_type_enum, f"v1 node type {v1_type!r} missing from v2 schema"


def test_schema_v2_score_vector_extensions_are_optional() -> None:
    """engine_corroboration and exploitability_evidence must be present
    in the score_vector properties but NOT in `required` — v1 records
    that omit them must continue to validate."""
    schema_path = repo_root() / "schema" / "evidence.schema.json"
    schema = load_json(schema_path)
    score_props = schema["$defs"]["score_vector"]["properties"]
    score_required = schema["$defs"]["score_vector"]["required"]
    assert "engine_corroboration" in score_props
    assert "exploitability_evidence" in score_props
    assert "engine_corroboration" not in score_required
    assert "exploitability_evidence" not in score_required


def test_schema_v2_new_top_level_fields_are_optional() -> None:
    """disclosure_status, discovery_engine, finding_type must be in
    properties but not required."""
    schema_path = repo_root() / "schema" / "evidence.schema.json"
    schema = load_json(schema_path)
    top_props = schema["properties"]
    top_required = schema["required"]
    for field in ("disclosure_status", "discovery_engine", "finding_type"):
        assert field in top_props, f"v2 optional field {field!r} missing from properties"
        assert field not in top_required, f"v2 optional field {field!r} must not be required"


def test_six_new_schema_files_present() -> None:
    """ADR-0013 enumerates six new sibling schemas; all must be on disk."""
    schema_dir = repo_root() / "schema"
    for name in (
        "discovery-run.schema.json",
        "crash.schema.json",
        "disagreement.schema.json",
        "invariant-violation.schema.json",
        "cross-target-candidate.schema.json",
        "disclosure-event.schema.json",
    ):
        assert (schema_dir / name).is_file(), f"v2 sibling schema {name!r} missing"
