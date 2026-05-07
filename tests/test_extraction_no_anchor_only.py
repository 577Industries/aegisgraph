"""Phase 1 contract: no record's evidence_source contains the Phase 0
placeholder strings.

This is the single hardest line in the bug we're fixing: "Replace
anchor-only graph records (every record in extraction/output/*/graph.json
currently has evidence_source='phase0 extraction placeholder, anchor-only')
with regenerated graph nodes/edges from real CodeQL queries, Semgrep
rules, an AndroidManifest analyzer, and an offline MobSF run."

Even when the current dev environment doesn't have CodeQL/MobSF docker, the
output must NOT carry "phase0" or "placeholder" tokens — the honest
substitute is "baseline_anchor_pending_toolchain:<sha256>". See
extraction/BUILD_STATUS.md for the toolchain availability matrix.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from aegisgraph.extraction import run_extract


PHASE0_TOKENS = (
    "phase0 extraction placeholder",
    "phase0 map placeholder",
    "phase0 placeholder",
    "anchor-only,",  # the literal phrase from the v0.3 evidence_source string
)


def _seed(tmp_path: Path) -> dict[str, dict]:
    shutil.copytree("schema", tmp_path / "schema")
    run_extract(tmp_path)
    out: dict[str, dict] = {}
    for graph_path in sorted((tmp_path / "extraction" / "output").glob("*/graph.json")):
        out[str(graph_path.relative_to(tmp_path))] = json.loads(graph_path.read_text())
    return out


def test_no_evidence_source_carries_phase0_token(tmp_path: Path) -> None:
    """Every record's evidence_source — both at the top-level nodes list AND
    inside each record.nodes — must be free of phase0/placeholder tokens.

    We check the full flat JSON because phase0 leakage might appear in any
    field (label, evidence_source, provenance.source, evidence_refs[*].command, ...).
    """
    graphs = _seed(tmp_path)
    assert graphs, "extraction emitted zero graphs"
    for path, graph in graphs.items():
        flat = json.dumps(graph)
        for token in PHASE0_TOKENS:
            assert token not in flat, f"{path} carries forbidden phase0 token: {token!r}"


def test_evidence_source_per_node_is_non_empty_and_typed(tmp_path: Path) -> None:
    """Each node.evidence_source MUST be a non-empty string with a known
    prefix:
      - <query_id>:<sarif_hash>          (codeql)
      - <check_id>:<json_hash>           (semgrep)
      - manifest:<sha256>                 (manifest)
      - mobsf:<section>:<sha256>          (mobsf)
      - baseline_anchor_pending_toolchain:<sha256>  (no-tools fallback)
    """
    graphs = _seed(tmp_path)
    valid_prefixes = (
        "aegisgraph/",  # codeql query id
        "aegisgraph.",  # semgrep rule id
        "manifest:",
        "mobsf:",
        "baseline_anchor_pending_toolchain:",
    )
    for path, graph in graphs.items():
        for record in graph.get("records", []):
            for node in record.get("nodes", []):
                es = node.get("evidence_source", "")
                assert isinstance(es, str) and es, f"{path}: node.evidence_source missing"
                assert es.startswith(valid_prefixes), (
                    f"{path}: unexpected evidence_source prefix in {node.get('id')!r}: {es!r}"
                )


def test_manifest_status_is_phase1(tmp_path: Path) -> None:
    """extraction/output/manifest.json status must be the new value.

    The Phase 0 string was 'phase0_anchor_only'; we require 'phase1_real_extraction'.
    """
    shutil.copytree("schema", tmp_path / "schema")
    run_extract(tmp_path)
    manifest = json.loads((tmp_path / "extraction" / "output" / "manifest.json").read_text())
    assert manifest["status"] == "phase1_real_extraction"


def test_per_target_coverage_includes_tool_run_status(tmp_path: Path) -> None:
    """coverage.json must list per-tool run status. The manifest tool MAY be
    'skipped_pending_target_source' in the current dev env (no clone), but
    the key MUST be present so downstream consumers can detect 'tool exists,
    didn't run' vs 'tool unknown'."""
    shutil.copytree("schema", tmp_path / "schema")
    run_extract(tmp_path)
    for cov_path in sorted((tmp_path / "extraction" / "output").glob("*/coverage.json")):
        coverage = json.loads(cov_path.read_text())
        tools = coverage.get("tool_run_status", {})
        for required in ("manifest", "codeql", "semgrep", "mobsf"):
            assert required in tools, f"{cov_path}: missing tool_run_status.{required}"
            assert tools[required].get("status") in {
                "ran",
                "skipped",
                "skipped_pending_toolchain",
                "skipped_pending_target_source",
                "failed",
            }, tools[required]
