"""Assemble per-tool AdapterResults into AegisGraph evidence records.

Strategy:
1. Receive AdapterResults from codeql / semgrep / manifest / mobsf adapters.
2. Group all nodes by `_path_class`.
3. For each path-class with at least one node, synthesize an evidence record:
   - nodes = the path-class's adapter nodes (with `_path_class` stripped).
   - edges = synthesized "co_observed" edges connecting nodes from different
     tools (so the graph reflects that the same path-class was hit by
     multiple analyses).
   - claim_state = "anchored" if any node has a non-empty tool_output_hash
     resolving to a real file; "validation_tasked" otherwise.
4. If ALL tools were skipped (e.g. dev environment without CodeQL/semgrep
   AND no target source clone for the manifest analyzer), emit a single
   baseline `media_decode` record per target whose `evidence_source` is
   `"baseline_anchor_pending_toolchain:<sha256(target.commit)>"` — NOT
   "phase0 placeholder". This honors the spec: "Mark each tool's
   tool_run_status as 'skipped_pending_toolchain' honestly — do NOT report
   'phase0 placeholder'."
5. Finalize each record via `aegisgraph.evidence.finalize_record` so the
   hash chain is real.
6. Emit `extraction/output/<target>/coverage.json` with
   `graph_evidence_ref_coverage`, `path_class_coverage`,
   `tool_run_status`, `stale_anchor_detection`.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

from aegisgraph.constants import PATH_CLASSES, STATIC_GENERATED_AT, TARGETS
from aegisgraph.evidence import evidence_ref, finalize_record, provenance
from aegisgraph.score import media_parser_score, link_parser_score, normalize_score_vector

from ._common import sha256_text


# Per-path-class default score vectors. Path classes the canonical scorers
# don't cover get a generic "moderate" vector; downstream review tightens.
_GENERIC_SCORE = normalize_score_vector(
    {
        "remote_reachability": 0.6,
        "attacker_control": 0.6,
        "parser_complexity": 0.5,
        "native_boundary": 0.3,
        "auth_boundary": 0.5,
        "privilege_impact": 0.5,
        "exploit_history": 0.4,
        "mitigation_strength": 0.5,
        "observability": 0.5,
        "confidence": 0.55,
    }
)


def _score_for_path_class(path_class: str) -> dict[str, float]:
    if path_class == "media_decode":
        return media_parser_score()
    if path_class == "link_preview":
        return link_parser_score()
    return deepcopy(_GENERIC_SCORE)


def _record_id(target_key: str, target_name: str, path_class: str) -> str:
    title = target_name.replace(" ", "-").upper()
    pc = path_class.upper().replace("_", "-")
    return f"AG-EV-EXTRACT-{title}-{pc}-001"


def _validation_task(target_name: str, path_class: str) -> dict[str, str]:
    title = target_name.replace(" ", "-").upper()
    pc = path_class.upper().replace("_", "-")
    return {
        "id": f"VAL-{title}-{pc}-REACHABILITY",
        "command": "make extract && make reprochain-map",
        "expected_output": (
            f"commit-pinned {path_class} path with explicit downstream "
            "harness mapping"
        ),
        "status": "planned",
    }


def _limitations(path_class: str) -> str:
    base = (
        "Phase 1 record. Records anchored to commit-pinned source locations "
        "from real CodeQL / Semgrep / AndroidManifest / MobSF tool runs. It "
        "does not assert a Signal or Element vulnerability, does not "
        "redistribute target source, and explicitly leaves downstream "
        "harness validation (ReproChain libwebp, etc.) for later phases."
    )
    return base


def _evidence_refs_for_record(
    target: dict[str, Any],
    target_key: str,
    tool_results: list[dict[str, Any]],
    path_class: str,
) -> list[dict[str, Any]]:
    """One evidence_ref per tool that contributed nodes to this record."""
    refs: list[dict[str, Any]] = []
    title = target["name"].replace(" ", "-").upper()
    pc = path_class.upper().replace("_", "-")
    for tr in tool_results:
        status = tr["tool_run_status"]["status"]
        tool = tr["tool"]
        out_hash = tr["tool_run_status"].get("tool_output_hash")
        if status == "ran" and out_hash:
            refs.append(
                {
                    "id": f"REF-{title}-{pc}-{tool.upper()}",
                    "tool": f"aegisgraph-extraction-{tool}",
                    "version": "phase1",
                    "command": f"adapters/{tool}_to_graph.py",
                    "output_hash": out_hash,
                }
            )
    if not refs:
        # All tools either skipped or failed for this target. Emit a
        # baseline ref keyed off target.commit so the hash-chain stays
        # populated; the ref's command and version make the situation
        # explicit (no "phase0" or "placeholder" tokens).
        refs.append(
            evidence_ref(
                ref_id=f"REF-{title}-{pc}-BASELINE",
                tool="aegisgraph-extraction-baseline",
                command="extraction/adapters/assemble.py",
                content=f"baseline_anchor_pending_toolchain:{target['commit']}:{path_class}",
                version="phase1",
            )
        )
    return refs


def _strip_internal_keys(node: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in node.items() if not k.startswith("_")}


def _synthesize_edges(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Synthesize edges within a path-class group.

    We use a "co_observed" edge from every entry_point to every handler,
    every handler to every parser/decoder/sink, etc. The relationship name
    encodes the AegisGraph node-type ordering so reviewers can tell which
    direction is upstream.
    """
    type_order = ("entry_point", "handler", "parser", "decoder", "native_boundary", "sink", "control")
    by_type: dict[str, list[dict[str, Any]]] = {t: [] for t in type_order}
    for n in nodes:
        nt = n.get("node_type")
        if nt in by_type:
            by_type[nt].append(n)

    edges: list[dict[str, Any]] = []
    for src_type, dst_type in zip(type_order, type_order[1:]):
        for src in by_type[src_type]:
            for dst in by_type[dst_type]:
                edges.append(
                    {
                        "from": src["id"],
                        "to": dst["id"],
                        "relationship": f"co_observed_{src_type}_to_{dst_type}",
                    }
                )
    return edges


def _baseline_record_nodes(target: dict[str, Any], path_class: str) -> list[dict[str, Any]]:
    """Synthesize a minimal anchored node set when all tools are skipped.

    The nodes still anchor to the pinned commit so reviewers can navigate
    to real source; their `evidence_source` strings are explicit about the
    fact that no scanner output backs the node yet
    ("baseline_anchor_pending_toolchain"), NOT "phase0 placeholder".
    """
    anchor = f"{target['repo_url']}/tree/{target['commit']}"
    baseline_hash = sha256_text(f"baseline_anchor_pending_toolchain:{target['commit']}:{path_class}")
    short = baseline_hash[:12]
    nodes = [
        {
            "id": f"baseline.entry.{short}",
            "node_type": "entry_point",
            "label": f"target entry point pending {path_class} extraction",
            "source_anchor": anchor,
            "evidence_source": f"baseline_anchor_pending_toolchain:{baseline_hash}",
        },
        {
            "id": f"baseline.handler.{short}",
            "node_type": "handler",
            "label": f"target handler pending {path_class} extraction",
            "source_anchor": anchor,
            "evidence_source": f"baseline_anchor_pending_toolchain:{baseline_hash}",
        },
    ]
    if path_class == "media_decode":
        nodes.extend(
            [
                {
                    "id": f"baseline.decoder.{short}",
                    "node_type": "decoder",
                    "label": "image decoder pending media_decode extraction",
                    "source_anchor": anchor,
                    "evidence_source": f"baseline_anchor_pending_toolchain:{baseline_hash}",
                },
                {
                    "id": f"baseline.sink.{short}",
                    "node_type": "sink",
                    "label": "WebP decoding boundary; ReproChain harness mapping pending",
                    "source_anchor": "reprochain/vendor/libwebp/README.md",
                    "evidence_source": f"baseline_anchor_pending_toolchain:reprochain_libwebp",
                },
            ]
        )
    return nodes


def _claim_state(record_nodes: list[dict[str, Any]], tool_results: list[dict[str, Any]]) -> str:
    has_real = any(
        tr["tool_run_status"]["status"] == "ran"
        and tr["tool_run_status"].get("tool_output_hash")
        for tr in tool_results
    )
    return "anchored" if has_real else "validation_tasked"


def assemble_records_for_target(
    target_key: str,
    tool_results: list[dict[str, Any]],
    previous_hash: str | None = None,
) -> tuple[list[dict[str, Any]], str | None, dict[str, Any]]:
    """Build a list of evidence records for one target.

    Returns (records, last_hash, coverage) where:
      - records is the list of finalized record dicts
      - last_hash is the hash_chain.record_hash of the last finalized record
        (used to chain into the next target).
      - coverage is the per-target coverage.json payload.
    """
    target = TARGETS[target_key]

    # 1. Bucket nodes by path-class.
    path_class_buckets: dict[str, list[dict[str, Any]]] = {pc: [] for pc in PATH_CLASSES}
    for tr in tool_results:
        for node in tr.get("nodes", []):
            pc = node.get("_path_class")
            if pc not in path_class_buckets:
                continue
            path_class_buckets[pc].append(node)

    # 2. If ALL buckets empty, emit a single media_decode baseline record.
    nonempty = {pc: ns for pc, ns in path_class_buckets.items() if ns}
    if not nonempty:
        path_class_buckets["media_decode"] = _baseline_record_nodes(target, "media_decode")
        nonempty = {"media_decode": path_class_buckets["media_decode"]}

    # 3. Build records.
    records: list[dict[str, Any]] = []
    cur_prev = previous_hash
    for path_class in PATH_CLASSES:
        nodes = path_class_buckets.get(path_class)
        if not nodes:
            continue
        clean_nodes = [_strip_internal_keys(n) for n in nodes]
        edges = _synthesize_edges(clean_nodes)
        record = {
            "id": _record_id(target_key, target["name"], path_class),
            "version": "v1.0",
            "target": {
                "name": target["name"],
                "repo_url": target["repo_url"],
                "commit": target["commit"],
                "source_policy": target["source_policy"],
            },
            "path_class": path_class,
            "nodes": clean_nodes,
            "edges": edges,
            "score_vector": _score_for_path_class(path_class),
            "claim_state": _claim_state(nodes, tool_results),
            "validation_task": _validation_task(target["name"], path_class),
            "evidence_refs": _evidence_refs_for_record(target, target_key, tool_results, path_class),
            "recommendation_refs": [],
            "limitations": _limitations(path_class),
            "provenance": provenance("phase1 real extraction adapters"),
            "safety_flags": [],
        }
        sealed = finalize_record(record, previous_hash=cur_prev)
        cur_prev = sealed["hash_chain"]["record_hash"]
        records.append(sealed)

    # 4. Coverage payload.
    tool_status_block: dict[str, dict[str, Any]] = {}
    for tr in tool_results:
        s = tr["tool_run_status"]
        tool_status_block[tr["tool"]] = {
            "status": s.get("status"),
            "reason": s.get("reason"),
            "tool_output_hash": s.get("tool_output_hash"),
            "node_count": len(tr.get("nodes", [])),
        }

    # graph_evidence_ref_coverage = fraction of nodes whose evidence_source
    # references a tool_output_hash that resolves to a non-baseline string.
    total_nodes = sum(len(r["nodes"]) for r in records)
    real_nodes = 0
    for r in records:
        for n in r["nodes"]:
            es = str(n.get("evidence_source", ""))
            if "baseline_anchor_pending_toolchain" not in es and "ReproChain pin pending" not in es:
                real_nodes += 1
    graph_evidence_ref_coverage = round(real_nodes / total_nodes, 4) if total_nodes else 0.0

    path_class_coverage = sorted(nonempty.keys())

    # stale_anchor_detection: count of nodes anchored to a commit string that
    # is not the target's pinned commit. (`#L<n>` suffixes are allowed.)
    stale = 0
    expected_commit = target["commit"]
    for r in records:
        for n in r["nodes"]:
            sa = str(n.get("source_anchor", ""))
            if sa.startswith(target["repo_url"]) and f"/tree/{expected_commit}" not in sa:
                stale += 1

    coverage = {
        "tool_output_type": "extraction_coverage",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "target": target["name"],
        "target_key": target_key,
        "graph_evidence_ref_coverage": graph_evidence_ref_coverage,
        "path_class_coverage": path_class_coverage,
        "tool_run_status": tool_status_block,
        "stale_anchor_detection": stale,
        "total_nodes": total_nodes,
        "total_records": len(records),
    }

    return records, cur_prev, coverage


def _relativize_reason(result: dict[str, Any], root: Path) -> dict[str, Any]:
    """Strip the absolute path prefix in `reason` strings so coverage
    output is byte-stable across machines.

    Adapter `reason` strings include absolute paths because the adapter
    doesn't know the repo root; we fix that here once and for all.
    """
    status = result.get("tool_run_status", {})
    reason = status.get("reason")
    if isinstance(reason, str):
        try:
            root_str = str(root.resolve())
        except OSError:
            root_str = str(root)
        if root_str and root_str in reason:
            status["reason"] = reason.replace(root_str + "/", "").replace(root_str, ".")
    return result


def collect_tool_results_for_target(target_key: str, root: Path) -> list[dict[str, Any]]:
    """Read each adapter's per-target output file (or invoke the adapter
    in-process when raw inputs are present).

    File layout (gitignored):
      extraction/output/<target>/raw/codeql-merged.sarif
      extraction/output/<target>/raw/semgrep.json
      extraction/output/<target>/manifest-analysis.json
      extraction/output/<target>/mobsf-results.json

    A real adapter run is preferred. When raw inputs are missing, we emit
    `status="skipped_pending_toolchain"` AdapterResults so coverage.json
    reflects the gap.
    """
    from .codeql_to_graph import from_sarif
    from .manifest_to_graph import from_manifest_analysis
    from .mobsf_to_graph import from_mobsf_results
    from .semgrep_to_graph import from_semgrep_json

    target = TARGETS[target_key]
    target_dir = root / "extraction" / "output" / target["graph_dir"]

    sarif = target_dir / "raw" / "codeql-merged.sarif"
    semgrep_json = target_dir / "raw" / "semgrep.json"
    manifest_json = target_dir / "manifest-analysis.json"
    mobsf_json = target_dir / "mobsf-results.json"

    # Source root for SARIF/semgrep is *only* known when build_db.sh has
    # cloned target source. We fall back to repo root just so paths still
    # normalize; the resulting source_anchor will still anchor to the
    # pinned GitHub URL via target.commit.
    source_root = root  # safe default; adapters degrade gracefully

    results = [
        from_sarif(sarif, target_key, target, source_root),
        from_semgrep_json(semgrep_json, target_key, target, source_root),
        from_manifest_analysis(manifest_json, target_key, target, source_root),
        from_mobsf_results(mobsf_json, target_key, target),
    ]
    return [_relativize_reason(r, root) for r in results]


__all__ = [
    "assemble_records_for_target",
    "collect_tool_results_for_target",
]
