"""Phase 1 real-extraction entry points.

Replaces the Phase 0 anchor-only scaffold with a pipeline that calls the
real adapters in `extraction/adapters/`. Each adapter normalizes raw output
from a real scanner (CodeQL SARIF, Semgrep JSON, AndroidManifest analysis,
MobSF JSON) into AegisGraph nodes/edges. `extraction.adapters.assemble`
buckets nodes by path-class, synthesizes intra-class edges, and finalizes
each record's hash chain.

Public API preserved:
  * `make_media_reachability_record(target_key, previous_hash=None)` — returns
    a single finalized media_decode evidence record. Used by the
    schema/validation tests.
  * `run_extract(root)` — writes per-target `graph.json`, per-target
    `coverage.json`, and the top-level `manifest.json` with status
    `"phase1_real_extraction"`.

The previous Phase 0 placeholder strings ("phase0 extraction placeholder,
anchor-only", "phase0 map placeholder") are no longer emitted anywhere in
this module's output. When tools are not available in the current
environment, records carry honest
`baseline_anchor_pending_toolchain:<sha256>` evidence_source markers so
later runs replace them cleanly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from extraction.adapters.assemble import (
    assemble_records_for_target,
    collect_tool_results_for_target,
)

from .constants import STATIC_GENERATED_AT, TARGETS
from .io import write_json


def make_media_reachability_record(
    target_key: str, previous_hash: str | None = None
) -> dict[str, Any]:
    """Return a single finalized media_decode evidence record.

    Used by tests/test_schema_validation.py to verify that extraction's
    output continues to validate against the v1 schema. We assemble a full
    target's records and pluck the media_decode record. If the
    media_decode bucket happens to be empty (because no tool found a
    decoder for that target), we fall back to the first record so the test
    contract — "extraction emits a v1.0-valid record" — still holds.
    """
    root = Path(__file__).resolve().parents[1]
    tool_results = collect_tool_results_for_target(target_key, root)
    records, _last, _coverage = assemble_records_for_target(
        target_key, tool_results, previous_hash=previous_hash
    )
    for record in records:
        if record["path_class"] == "media_decode":
            return record
    if records:
        return records[0]
    raise RuntimeError(
        f"extraction emitted no records for target_key={target_key!r}; "
        "this should never happen because assemble_records_for_target "
        "always emits a baseline record."
    )


def run_extract(root: Path) -> dict[str, Any]:
    """Write per-target graph.json + coverage.json and the top-level
    manifest.json. Returns the manifest dict.

    Output layout:
      extraction/output/{signal,element-x}/graph.json
      extraction/output/{signal,element-x}/coverage.json
      extraction/output/manifest.json
    """
    outputs: list[str] = []
    coverage_outputs: list[str] = []
    previous_hash: str | None = None
    aggregate_tool_status: dict[str, dict[str, Any]] = {}

    for target_key, target in TARGETS.items():
        tool_results = collect_tool_results_for_target(target_key, root)
        records, last_hash, coverage = assemble_records_for_target(
            target_key, tool_results, previous_hash=previous_hash
        )
        previous_hash = last_hash if last_hash is not None else previous_hash

        # Build the on-disk graph payload.
        # `nodes` and `edges` at the top level mirror the union of all per-record
        # nodes and edges; `records` carries the canonical per-record set.
        all_nodes: list[dict[str, Any]] = []
        all_edges: list[dict[str, Any]] = []
        for record in records:
            all_nodes.extend(record["nodes"])
            all_edges.extend(record["edges"])

        graph = {
            "tool_output_type": "extraction_graph",
            "version": "v1.0",
            "generated_by": "aegisgraph-tier3-research",
            "generated_at": STATIC_GENERATED_AT,
            "safety_posture": "private_by_default",
            "target": target["name"],
            "source_policy": "anchor-only",
            "records": records,
            "nodes": all_nodes,
            "edges": all_edges,
        }
        graph_path = root / "extraction" / "output" / target["graph_dir"] / "graph.json"
        write_json(graph_path, graph)
        outputs.append(str(graph_path.relative_to(root)))

        coverage_path = root / "extraction" / "output" / target["graph_dir"] / "coverage.json"
        write_json(coverage_path, coverage)
        coverage_outputs.append(str(coverage_path.relative_to(root)))

        # Aggregate the per-target tool_run_status for the top-level manifest.
        for tool_key, tool_block in coverage.get("tool_run_status", {}).items():
            aggregate_tool_status.setdefault(target_key, {})[tool_key] = tool_block

    manifest = {
        "tool_output_type": "extraction_manifest",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "outputs": outputs,
        "coverage_outputs": coverage_outputs,
        "tool_run_status": aggregate_tool_status,
        "status": "phase1_real_extraction",
    }
    write_json(root / "extraction" / "output" / "manifest.json", manifest)
    return manifest
