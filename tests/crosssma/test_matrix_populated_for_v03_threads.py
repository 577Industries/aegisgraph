"""Matrix populated for the 6 v0.3 threads test.

CrossSMA M5.5 must produce a 6-thread × 4-target = 24-cell matrix for
the v0.3 evidence threads: SIG-GP-001/002/003 + ELX-GP-001/002/003.

Each row is one AG-XSMA-* record with 4 target cells. Per plan §15
R-ENG-4, default claim_state for unverified reachability is anchored
(here: candidate_path), NOT validation_tasked. The source target cell
is confirmed_reachable.
"""

from __future__ import annotations

from aegisgraph.crosssma.matrix_renderer import (
    GraphThread,
    render_matrix,
    v03_graph_threads,
)
from aegisgraph.crosssma.target_registry import load_registry


def test_v03_graph_threads_returns_six_threads() -> None:
    threads = v03_graph_threads()
    assert len(threads) == 6
    thread_ids = sorted(t.thread_id for t in threads)
    assert thread_ids == sorted(
        ["SIG-GP-001", "SIG-GP-002", "SIG-GP-003",
         "ELX-GP-001", "ELX-GP-002", "ELX-GP-003"]
    )


def test_each_thread_has_valid_source_target() -> None:
    """Every v0.3 thread must point at a known target_id in the registry."""
    threads = v03_graph_threads()
    registry = load_registry()
    for thread in threads:
        assert thread.source_target_id in registry, (
            f"Thread {thread.thread_id} sources unknown target "
            f"{thread.source_target_id!r}"
        )


def test_matrix_renders_24_cells_across_6_threads() -> None:
    """6 threads × 4 targets = 24 cells (one row per record, four
    target_findings per record). 24 total target_findings entries."""
    threads = v03_graph_threads()
    registry = load_registry()
    records = render_matrix(threads, registry)
    assert len(records) == 6
    total_cells = sum(len(r["target_findings"]) for r in records)
    assert total_cells == 24, (
        f"expected 24 matrix cells (6×4), got {total_cells}"
    )


def test_each_record_has_four_target_cells() -> None:
    threads = v03_graph_threads()
    registry = load_registry()
    records = render_matrix(threads, registry)
    for record in records:
        assert len(record["target_findings"]) == 4, (
            f"record {record['candidate_id']} has "
            f"{len(record['target_findings'])} cells, expected 4"
        )


def test_source_target_cell_marked_confirmed_reachable() -> None:
    threads = v03_graph_threads()
    registry = load_registry()
    records = render_matrix(threads, registry)
    for record, thread in zip(records, threads):
        source_cells = [
            c for c in record["target_findings"]
            if c["target"] == thread.source_target_id
        ]
        assert len(source_cells) == 1, (
            f"record {record['candidate_id']} missing source cell for "
            f"{thread.source_target_id}"
        )
        assert source_cells[0]["status"] == "confirmed_reachable"


def test_non_source_target_default_status_is_candidate_path_or_dependency_absent() -> None:
    """Per plan §15 R-ENG-4: default claim_state is anchored, not
    validation_tasked. In matrix terms: cells default to candidate_path
    when a dependency match exists, else dependency_absent."""
    threads = v03_graph_threads()
    registry = load_registry()
    records = render_matrix(threads, registry)
    allowed = {"candidate_path", "dependency_absent", "confirmed_reachable"}
    for record in records:
        for cell in record["target_findings"]:
            assert cell["status"] in allowed, (
                f"cell {cell} carries disallowed status {cell['status']!r}"
            )


def test_all_records_validate_against_schema() -> None:
    """Round-trip schema validation for all 6 v0.3 records."""
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    from aegisgraph.io import load_json, repo_root

    schema_dir = repo_root() / "schema"
    cross_schema = load_json(schema_dir / "cross-target-candidate.schema.json")
    hash_chain_schema = load_json(schema_dir / "hash-chain.schema.json")
    sref = Registry().with_resources(
        [
            (cross_schema["$id"], Resource.from_contents(cross_schema)),
            ("hash-chain.schema.json", Resource.from_contents(hash_chain_schema)),
            (hash_chain_schema["$id"], Resource.from_contents(hash_chain_schema)),
        ]
    )
    threads = v03_graph_threads()
    registry = load_registry()
    records = render_matrix(threads, registry)
    validator = Draft202012Validator(cross_schema, registry=sref)
    for record in records:
        errors = sorted(validator.iter_errors(record), key=str)
        assert not errors, (
            f"record {record['candidate_id']} schema errors: "
            + "; ".join(
                f"{'/'.join(str(p) for p in e.path)}: {e.message}"
                for e in errors
            )
        )


def test_all_records_have_unique_candidate_ids() -> None:
    threads = v03_graph_threads()
    registry = load_registry()
    records = render_matrix(threads, registry)
    ids = [r["candidate_id"] for r in records]
    assert len(set(ids)) == len(ids), (
        f"duplicate candidate_ids across the 6 v0.3 rows: {ids}"
    )
