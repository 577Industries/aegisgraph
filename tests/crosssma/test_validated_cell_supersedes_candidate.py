"""Wave 9B (M9.2) — AG-XSMA-VALIDATED-SIG-GP-001-ELX schema + supersedes
+ hash-chain contract test.

Asserts:
  * the validated record validates against
    schema/cross-target-candidate.schema.json (with the v0.4/Wave 9B
    validation-overlay fields);
  * `supersedes` points at the prior candidate AG-XSMA-SIG-GP-001;
  * the new record's `hash_chain.previous_hash` equals the prior
    candidate record's `hash_chain.record_hash`;
  * the new record's own hash chain verifies.

The prior candidate record is reconstructed in-memory via the same
matrix_renderer call that the Wave 3 scaffold uses for SIG-GP-001 —
this is the deterministic, hash-stable origin record we promote here.
"""

from __future__ import annotations

import re
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from aegisgraph.crosssma.matrix_renderer import (
    GraphThread,
    render_matrix,
    v03_graph_threads,
)
from aegisgraph.crosssma.target_registry import load_registry
from aegisgraph.crosssma.validation.elementx_linkpreview_xsma import (
    build_validation_record,
    validated_record_path,
)
from aegisgraph.hashchain import verify_hash_chain
from aegisgraph.io import load_json, repo_root


def _load_validated_record() -> dict:
    return load_json(validated_record_path())


def _make_prior_candidate_sig_gp_001() -> dict:
    """Reconstruct the SIG-GP-001 candidate via the same renderer used
    in Wave 3. Deterministic: same `STATIC_GENERATED_AT`, same
    `GraphThread` fixture from `v03_graph_threads`."""
    threads = [t for t in v03_graph_threads() if t.thread_id == "SIG-GP-001"]
    assert len(threads) == 1, "SIG-GP-001 missing from v03 fixture"
    registry = load_registry()
    records = render_matrix(threads, registry)
    assert len(records) == 1
    assert records[0]["candidate_id"] == "AG-XSMA-SIG-GP-001"
    return records[0]


def test_validated_record_file_exists() -> None:
    path = validated_record_path()
    assert path.exists(), (
        f"validated record file missing at {path}; expected "
        "AG-XSMA-VALIDATED-SIG-GP-001-ELX.json under "
        "crosssma/evidence/validated/"
    )


def test_validated_record_validates_against_schema() -> None:
    schema_dir = repo_root() / "schema"
    cross_schema = load_json(schema_dir / "cross-target-candidate.schema.json")
    hash_chain_schema = load_json(schema_dir / "hash-chain.schema.json")

    registry_ref = Registry().with_resources(
        [
            (cross_schema["$id"], Resource.from_contents(cross_schema)),
            ("hash-chain.schema.json", Resource.from_contents(hash_chain_schema)),
            (hash_chain_schema["$id"], Resource.from_contents(hash_chain_schema)),
        ]
    )
    record = _load_validated_record()
    validator = Draft202012Validator(cross_schema, registry=registry_ref)
    errors = sorted(validator.iter_errors(record), key=str)
    assert not errors, (
        "AG-XSMA-VALIDATED-* record failed schema validation: "
        + "; ".join(
            f"{'/'.join(str(p) for p in e.path)}: {e.message}"
            for e in errors
        )
    )


def test_validated_record_id_format() -> None:
    record = _load_validated_record()
    assert record["record_id"] == "AG-XSMA-VALIDATED-SIG-GP-001-ELX"
    assert re.fullmatch(
        r"AG-XSMA-VALIDATED-[A-Z0-9-]+", record["record_id"]
    ), f"record_id {record['record_id']!r} fails AG-XSMA-VALIDATED pattern"


def test_validated_record_supersedes_prior_candidate() -> None:
    """Plan §23 R-ENG-4 invariant: validation records carry an explicit
    pointer back to the candidate they supersede; reviewers must be
    able to walk the chain candidate -> validated without inference."""
    record = _load_validated_record()
    assert record["supersedes"] == "AG-XSMA-SIG-GP-001", (
        f"supersedes pointer {record['supersedes']!r} does not name the "
        "prior candidate AG-XSMA-SIG-GP-001"
    )
    assert record["candidate_id"] == "AG-XSMA-SIG-GP-001", (
        "candidate_id on a validation overlay must point at the "
        "candidate being promoted, not at the new record_id"
    )


def test_validated_record_hash_chain_links_to_prior_record() -> None:
    """previous_hash on the validation record == record_hash on the
    candidate record. The chain is what makes the lineage forgery-evident."""
    prior = _make_prior_candidate_sig_gp_001()
    prior_record_hash = prior["hash_chain"]["record_hash"]

    validated = _load_validated_record()
    chain_prev = validated["hash_chain"]["previous_hash"]
    assert chain_prev == prior_record_hash, (
        f"hash-chain link broken: validated.previous_hash={chain_prev!r} "
        f"does not equal prior candidate record_hash={prior_record_hash!r}"
    )


def test_validated_record_own_hash_chain_verifies() -> None:
    record = _load_validated_record()
    errors = verify_hash_chain(record)
    assert errors == [], f"hash chain failed on validated record: {errors}"


def test_validated_record_focus_cell_confirmed_reachable() -> None:
    """The Element X target_id cell — the one we promoted — must be
    confirmed_reachable. Other cells stay candidate_path / dependency_absent
    so we don't lie about un-validated cells."""
    record = _load_validated_record()
    assert record["target_id"] == "element-x-android"
    assert record["status"] == "confirmed_reachable"
    elx_cells = [
        c for c in record["target_findings"] if c["target"] == "element-x-android"
    ]
    assert len(elx_cells) == 1
    assert elx_cells[0]["status"] == "confirmed_reachable", (
        f"element-x-android cell on validation record is "
        f"{elx_cells[0]['status']!r}; expected confirmed_reachable"
    )


def test_validated_record_builder_emits_same_bytes_as_on_disk() -> None:
    """The on-disk record MUST be byte-identical to what the builder
    produces; otherwise the hash chain on disk drifts from the canonical
    builder output and reviewers can't reproduce it."""
    on_disk = _load_validated_record()
    rebuilt = build_validation_record()
    assert rebuilt == on_disk, (
        "build_validation_record() output diverges from on-disk JSON; "
        "regenerate the JSON file or fix the builder"
    )
