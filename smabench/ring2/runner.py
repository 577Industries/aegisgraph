"""Ring 2 runner — consumes real extraction outputs.

Loads `extraction/output/<target>/graph.json` for each target listed in
`aegisgraph.constants.TARGETS`, filters records by `path_class` and
`claim_state`, and aggregates a per-target benchmark score that
combines:

- `nodes_with_real_evidence_ratio` — fraction of graph nodes whose
  `evidence_source` doesn't match the phase-0 placeholder strings
  (`"phase0"`, `"placeholder"`, `"anchor-only"`). Real extraction will
  populate these with concrete tool names (codeql, semgrep, mobsf, etc.).
- `validation_task_passing_ratio` — fraction of records whose
  `validation_task.status == "passing"`.
- `path_class_coverage` — fraction of the eight ASEMA path classes
  represented at least once in the graph.

If extraction outputs are missing — which is the *expected* state when
this stream runs before `real-extraction` lands — we report
`status="ring2_pending_extraction"` rather than failing. The orchestrator
will surface this status in the top-level results.json so the lack of
upstream data is visible, not silent.

The runner does NOT mutate extraction outputs. It opens them read-only
and emits its own report at `smabench/results/<date>/ring2.json`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Constants imported from aegisgraph; this stream is allowed to read
# integration-owned modules but not mutate them.
from aegisgraph.constants import PATH_CLASSES, TARGETS


PHASE0_MARKERS = ("phase0", "placeholder", "anchor-only")


def _is_real_evidence(evidence_source: str) -> bool:
    text = (evidence_source or "").lower()
    return not any(marker in text for marker in PHASE0_MARKERS)


def _load_graph(graph_path: Path) -> dict[str, Any] | None:
    if not graph_path.is_file():
        return None
    try:
        with graph_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError):
        return None


def _summarize_target(target_key: str, target: dict, graph: dict[str, Any] | None) -> dict[str, Any]:
    """Build a per-target Ring 2 summary.

    The summary is byte-stable given the same `graph`, which means
    Ring 2 contributes deterministic data to the top-level repeatability
    check.
    """

    if graph is None:
        return {
            "target": target_key,
            "name": target["name"],
            "graph_path": f"extraction/output/{target['graph_dir']}/graph.json",
            "status": "missing_extraction_output",
            "node_count": 0,
            "record_count": 0,
            "nodes_with_real_evidence": 0,
            "nodes_with_real_evidence_ratio": 0.0,
            "validation_task_passing_count": 0,
            "validation_task_total": 0,
            "validation_task_passing_ratio": 0.0,
            "path_class_coverage_count": 0,
            "path_class_coverage_total": len(PATH_CLASSES),
            "path_class_coverage_ratio": 0.0,
            "score": 0.0,
            "referenced_node_ids": [],
        }

    nodes = list(graph.get("nodes", []))
    records = list(graph.get("records", []))

    real_count = sum(1 for node in nodes if _is_real_evidence(str(node.get("evidence_source", ""))))
    real_ratio = (real_count / len(nodes)) if nodes else 0.0

    passing_count = 0
    validation_task_total = 0
    path_classes_seen: set[str] = set()
    for record in records:
        task = record.get("validation_task") or {}
        if "status" in task:
            validation_task_total += 1
            if str(task.get("status")).lower() == "passing":
                passing_count += 1
        path_class = record.get("path_class")
        if path_class in PATH_CLASSES:
            path_classes_seen.add(path_class)

    passing_ratio = (passing_count / validation_task_total) if validation_task_total else 0.0
    path_coverage_ratio = len(path_classes_seen) / len(PATH_CLASSES)

    # Aggregate score: equal-weighted convex combination of the three
    # ratios. Capped at 1.0 by construction. We prefer a transparent
    # arithmetic mean here over a tuned weight vector — the SPEC's
    # "ring2 benchmark score" is meant to be auditable, not optimal.
    score = round((real_ratio + passing_ratio + path_coverage_ratio) / 3.0, 3)

    referenced_ids = sorted({str(node.get("id")) for node in nodes if node.get("id")})

    if real_count == 0 and passing_count == 0 and len(path_classes_seen) <= 1:
        status = "extraction_phase0_only"
    elif real_count > 0 and passing_count > 0:
        status = "ring2_real_evidence_present"
    else:
        status = "ring2_partial"

    return {
        "target": target_key,
        "name": target["name"],
        "graph_path": f"extraction/output/{target['graph_dir']}/graph.json",
        "status": status,
        "node_count": len(nodes),
        "record_count": len(records),
        "nodes_with_real_evidence": real_count,
        "nodes_with_real_evidence_ratio": round(real_ratio, 3),
        "validation_task_passing_count": passing_count,
        "validation_task_total": validation_task_total,
        "validation_task_passing_ratio": round(passing_ratio, 3),
        "path_class_coverage_count": len(path_classes_seen),
        "path_class_coverage_total": len(PATH_CLASSES),
        "path_class_coverage_ratio": round(path_coverage_ratio, 3),
        "path_classes_seen": sorted(path_classes_seen),
        "score": score,
        "referenced_node_ids": referenced_ids,
    }


def run(root: Path) -> dict[str, Any]:
    """Run the Ring 2 consumer pass.

    Returns a dict shaped for direct embedding under
    `results.json["rings"]["ring2"]`. Always returns a value; never
    raises on missing extraction inputs (caller relies on the
    `status` field).
    """

    target_summaries: list[dict[str, Any]] = []
    graphs_present = 0
    graphs_missing = 0
    for target_key, target in TARGETS.items():
        graph_path = root / "extraction" / "output" / target["graph_dir"] / "graph.json"
        graph = _load_graph(graph_path)
        if graph is None:
            graphs_missing += 1
        else:
            graphs_present += 1
        target_summaries.append(_summarize_target(target_key, target, graph))

    if graphs_present == 0:
        overall_status = "ring2_pending_extraction"
    elif graphs_missing > 0:
        overall_status = "ring2_partial_extraction"
    elif all(s["status"] == "ring2_real_evidence_present" for s in target_summaries):
        overall_status = "ring2_real_evidence_present"
    else:
        overall_status = "ring2_extraction_phase0"

    aggregate_score = (
        round(sum(s["score"] for s in target_summaries) / len(target_summaries), 3)
        if target_summaries
        else 0.0
    )

    return {
        "status": overall_status,
        "graphs_expected": len(TARGETS),
        "graphs_present": graphs_present,
        "graphs_missing": graphs_missing,
        "aggregate_score": aggregate_score,
        "targets": target_summaries,
        "inputs": [
            f"extraction/output/{TARGETS[k]['graph_dir']}/graph.json" for k in sorted(TARGETS.keys())
        ],
    }
