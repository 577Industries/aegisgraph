"""Top-N is sorted by score_total descending."""

from __future__ import annotations

import json
from pathlib import Path

from aegisgraph.hashchain import attach_hash_chain
from aegisgraph.workbench.packet_export import export_packet


def _scored_evidence_record(record_id: str, score_total: float) -> dict:
    base = {
        "id": record_id,
        "version": "v1.0",
        "claim_state": "observed",
        "target": {
            "name": "Synthetic",
            "repo_url": "https://example.invalid/foo",
            "commit": "abcd",
            "source_policy": "anchor-only",
        },
        "path_class": "media_decode",
        "discovery_engine": "extraction",
        "score_vector": {
            "remote_reachability": 0,
            "attacker_control": 0,
            "parser_complexity": 0,
            "native_boundary": 0,
            "auth_boundary": 0,
            "privilege_impact": 0,
            "exploit_history": 0,
            "mitigation_strength": 0,
            "observability": 0,
            "confidence": 0,
            "total": score_total,
        },
        "nodes": [
            {
                "id": f"node.{record_id}",
                "node_type": "entry_point",
                "label": "test",
                "source_anchor": "x",
                "evidence_source": "synthetic_test",
            }
        ],
        "edges": [],
        "evidence_refs": [],
        "recommendation_refs": [],
        "limitations": "Synthetic test record for top-N sort test (top-n).",
        "validation_task": {
            "id": "VT-X",
            "command": "true",
            "expected_output": "no output",
            "status": "planned",
        },
        "provenance": {
            "generated_by": "test",
            "generated_at": "2026-05-13T00:00:00Z",
            "source": "score-sort test",
            "private_by_default": True,
        },
        "safety_flags": [],
    }
    return attach_hash_chain(base)


def test_top_n_returns_highest_scored_records(tmp_path: Path) -> None:
    # Build a synthetic repo with 5 evidence records carrying different scores.
    scored = [
        _scored_evidence_record("AG-EV-S1", 1.1),
        _scored_evidence_record("AG-EV-S2", 4.4),
        _scored_evidence_record("AG-EV-S3", 7.7),
        _scored_evidence_record("AG-EV-S4", 2.2),
        _scored_evidence_record("AG-EV-S5", 5.5),
    ]
    graph_path = tmp_path / "extraction" / "output" / "synth" / "graph.json"
    graph_path.parent.mkdir(parents=True, exist_ok=True)
    graph_path.write_text(
        json.dumps({"records": scored}, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    out_dir = tmp_path / "exports" / "reviewer-packet"
    manifest = export_packet(tmp_path, top_n=3, out_dir=out_dir)
    ids = [f["record_id"] for f in manifest["findings"]]
    assert ids == ["AG-EV-S3", "AG-EV-S5", "AG-EV-S2"]


def test_top_n_zero_emits_no_findings(tmp_path: Path) -> None:
    record = _scored_evidence_record("AG-EV-ONE", 1.0)
    p = tmp_path / "extraction" / "output" / "x" / "graph.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps({"records": [record]}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    manifest = export_packet(
        tmp_path, top_n=0, out_dir=tmp_path / "exports" / "reviewer-packet"
    )
    assert manifest["findings"] == []
