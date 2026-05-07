"""Ring 2 reads real extraction outputs.

Two scenarios:

1. **Extraction outputs missing.** When `extraction/output/<target>/graph.json`
   doesn't exist (the expected state when this stream is merged before
   the `real-extraction` stream), Ring 2 must report
   `status="ring2_pending_extraction"` rather than crashing. Per-target
   summaries must report `status="missing_extraction_output"`.
2. **Extraction outputs present.** When the graphs exist, Ring 2 must
   reference at least one node from each target's graph in the per-
   target summary. The status must reflect the level of evidence: if
   every node still carries phase-0 markers we report
   `extraction_phase0_only`; if real evidence is present we report
   `ring2_real_evidence_present`.

These tests do not depend on the rest of the orchestrator — they
exercise `smabench.ring2.runner.run` directly so a Ring 2 regression
surfaces independently of Ring 1 generator changes.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegisgraph.constants import TARGETS
from smabench.ring2 import runner


def _make_extraction_graph(nodes_real_evidence: bool, validation_passing: bool) -> dict:
    """Synthesize a graph.json shaped like the integration's extraction output."""

    nodes = [
        {
            "id": "entry.inbound-media",
            "node_type": "entry_point",
            "label": "Inbound media path",
            "source_anchor": "https://github.com/example/repo/tree/abc",
            "evidence_source": (
                "codeql query results from extraction stage" if nodes_real_evidence else "phase0 placeholder"
            ),
        },
        {
            "id": "decoder.image-stack",
            "node_type": "decoder",
            "label": "Image decoder",
            "source_anchor": "https://github.com/example/repo/tree/abc",
            "evidence_source": (
                "semgrep policy hit on call site" if nodes_real_evidence else "phase0 anchor-only"
            ),
        },
    ]
    return {
        "tool_output_type": "extraction_graph",
        "version": "v1.0",
        "generated_by": "test",
        "generated_at": "2026-05-05T00:00:00Z",
        "safety_posture": "private_by_default",
        "target": "test target",
        "source_policy": "anchor-only",
        "nodes": nodes,
        "edges": [],
        "records": [
            {
                "id": "AG-EV-TEST-001",
                "version": "v1.0",
                "path_class": "media_decode",
                "claim_state": "validation_tasked",
                "validation_task": {
                    "id": "VAL-TEST",
                    "command": "make extract",
                    "expected_output": "ok",
                    "status": "passing" if validation_passing else "planned",
                },
                "nodes": nodes,
                "edges": [],
                "score_vector": {},
                "evidence_refs": [],
                "recommendation_refs": [],
                "limitations": "synthetic test fixture",
                "provenance": {},
                "safety_flags": [],
                "target": {},
            }
        ],
    }


def test_ring2_pending_extraction_when_outputs_missing(tmp_path: Path) -> None:
    """When no extraction outputs exist, the runner reports pending."""

    # tmp_path has no extraction/output/ subtree.
    result = runner.run(tmp_path)
    assert result["status"] == "ring2_pending_extraction"
    assert result["graphs_present"] == 0
    assert result["graphs_missing"] == len(TARGETS)
    for summary in result["targets"]:
        assert summary["status"] == "missing_extraction_output"
        assert summary["node_count"] == 0
        assert summary["referenced_node_ids"] == []


def test_ring2_real_evidence_present(tmp_path: Path) -> None:
    """When extraction outputs land with real evidence, status flips."""

    for target_key, target in TARGETS.items():
        graph_dir = tmp_path / "extraction" / "output" / target["graph_dir"]
        graph_dir.mkdir(parents=True, exist_ok=True)
        (graph_dir / "graph.json").write_text(
            json.dumps(_make_extraction_graph(True, True)), encoding="utf-8"
        )

    result = runner.run(tmp_path)
    assert result["status"] == "ring2_real_evidence_present"
    assert result["graphs_present"] == len(TARGETS)
    assert result["graphs_missing"] == 0
    # Each target summary references at least one node from its own
    # graph (this is the SPEC-mandated check).
    for summary in result["targets"]:
        assert summary["node_count"] > 0, summary
        assert summary["referenced_node_ids"], summary
        assert summary["nodes_with_real_evidence_ratio"] == 1.0
        assert summary["validation_task_passing_ratio"] == 1.0


def test_ring2_phase0_only_when_evidence_is_placeholder(tmp_path: Path) -> None:
    """When extraction outputs exist but all evidence is phase-0 markers."""

    for target_key, target in TARGETS.items():
        graph_dir = tmp_path / "extraction" / "output" / target["graph_dir"]
        graph_dir.mkdir(parents=True, exist_ok=True)
        (graph_dir / "graph.json").write_text(
            json.dumps(_make_extraction_graph(False, False)), encoding="utf-8"
        )

    result = runner.run(tmp_path)
    assert result["graphs_present"] == len(TARGETS)
    # When evidence is purely phase-0, status reflects that.
    for summary in result["targets"]:
        assert summary["status"] == "extraction_phase0_only", summary
        assert summary["nodes_with_real_evidence_ratio"] == 0.0


def test_ring2_against_in_repo_extraction_outputs(tmp_path: Path) -> None:
    """Sanity-check Ring 2 against the actual extraction output committed
    in the integration branch.

    We resolve the repo root from the test file location instead of
    `os.getcwd()` so this test is robust to pytest invocation cwd. If
    the in-repo extraction graphs have moved, the test gracefully
    skips rather than failing — Ring 2 is supposed to handle missing
    inputs, and that's what `test_ring2_pending_extraction_when_outputs_missing`
    proves.
    """

    repo_root = Path(__file__).resolve().parents[1]
    extraction_root = repo_root / "extraction" / "output"
    if not extraction_root.is_dir():
        return  # Nothing to verify; skip silently.
    result = runner.run(repo_root)
    assert result["graphs_expected"] == len(TARGETS)
    # Whether or not phase-0, every target should have a non-empty
    # node list because the integration branch ships scaffold graphs.
    for summary in result["targets"]:
        if summary["status"] == "missing_extraction_output":
            continue  # Real-extraction stream may not have landed yet.
        assert summary["node_count"] > 0
        assert summary["referenced_node_ids"]
