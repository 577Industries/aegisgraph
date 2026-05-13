"""Renderer overlap-matrix tests.

`aegisgraph.baseline_delta.renderer.compute_overlap_matrix` takes per-tool
normalized finding lists keyed by tool name and returns:

    {
      target: {
        category: {
          tool: count,
          "shared_with": {tool_a: [(category, location_hash), ...], ...},
        },
      },
      "_global": {
        "tools_present_at_location": {(category, location_hash): {tool, ...}},
      },
    }

We test it with hand-rolled synthetic input rather than real SARIF/JSON.
"""

from __future__ import annotations

from typing import Any

from aegisgraph.baseline_delta.renderer import (
    NormalizedFinding,
    compute_overlap_matrix,
)


def _finding(
    *,
    tool: str,
    target: str,
    category: str,
    rule_id: str,
    location_hash: str,
    severity: str = "warning",
) -> dict[str, Any]:
    return {
        "tool": tool,
        "target": target,
        "category": category,
        "rule_id": rule_id,
        "location_hash": location_hash,
        "severity": severity,
    }


def test_overlap_matrix_empty_input_produces_no_categories() -> None:
    matrix = compute_overlap_matrix(findings=[])
    assert matrix == {}


def test_overlap_matrix_single_tool_single_finding() -> None:
    f1 = _finding(
        tool="codeql",
        target="signal",
        category="url-fetch-no-policy",
        rule_id="INV-01",
        location_hash="abc123",
    )
    matrix = compute_overlap_matrix(findings=[f1])

    assert "signal" in matrix
    assert "url-fetch-no-policy" in matrix["signal"]
    cell = matrix["signal"]["url-fetch-no-policy"]
    assert cell["tool_counts"]["codeql"] == 1
    assert cell["tool_counts"].get("semgrep", 0) == 0
    assert cell["tool_counts"].get("aegisgraph", 0) == 0


def test_overlap_matrix_two_tools_same_location_is_shared() -> None:
    """Two tools reporting the same (category, location_hash) means they
    overlap at that exact spot. The matrix must mark this in
    `shared_locations`.
    """
    f_codeql = _finding(
        tool="codeql",
        target="signal",
        category="url-fetch-no-policy",
        rule_id="INV-01",
        location_hash="loc-001",
    )
    f_semgrep = _finding(
        tool="semgrep",
        target="signal",
        category="url-fetch-no-policy",
        rule_id="r2c.url-fetch-no-policy",
        location_hash="loc-001",
    )

    matrix = compute_overlap_matrix(findings=[f_codeql, f_semgrep])
    cell = matrix["signal"]["url-fetch-no-policy"]

    assert cell["tool_counts"]["codeql"] == 1
    assert cell["tool_counts"]["semgrep"] == 1
    # Location loc-001 is shared between codeql and semgrep:
    assert any(
        set(entry["tools"]) == {"codeql", "semgrep"}
        and entry["location_hash"] == "loc-001"
        for entry in cell["shared_locations"]
    )


def test_overlap_matrix_disjoint_locations_not_shared() -> None:
    """Same category but different location_hash => NOT shared. Just two
    parallel findings.
    """
    f_codeql = _finding(
        tool="codeql",
        target="element-x",
        category="webview-js-interface",
        rule_id="INV-09",
        location_hash="loc-A",
    )
    f_semgrep = _finding(
        tool="semgrep",
        target="element-x",
        category="webview-js-interface",
        rule_id="webview-js-interface-pattern",
        location_hash="loc-B",
    )

    matrix = compute_overlap_matrix(findings=[f_codeql, f_semgrep])
    cell = matrix["element-x"]["webview-js-interface"]

    assert cell["tool_counts"]["codeql"] == 1
    assert cell["tool_counts"]["semgrep"] == 1
    # No locations overlap so shared_locations is empty.
    assert cell["shared_locations"] == []


def test_overlap_matrix_per_target_isolation() -> None:
    """Findings against different targets must never collide in the
    matrix even if they share a (category, location_hash) — different
    targets are by definition different artifacts.
    """
    f_signal = _finding(
        tool="codeql",
        target="signal",
        category="url-fetch-no-policy",
        rule_id="INV-01",
        location_hash="loc-same",
    )
    f_elementx = _finding(
        tool="codeql",
        target="element-x",
        category="url-fetch-no-policy",
        rule_id="INV-01",
        location_hash="loc-same",
    )

    matrix = compute_overlap_matrix(findings=[f_signal, f_elementx])

    assert matrix["signal"]["url-fetch-no-policy"]["tool_counts"]["codeql"] == 1
    assert matrix["element-x"]["url-fetch-no-policy"]["tool_counts"]["codeql"] == 1
    # No cross-target shared rows.
    assert matrix["signal"]["url-fetch-no-policy"]["shared_locations"] == []
    assert matrix["element-x"]["url-fetch-no-policy"]["shared_locations"] == []


def test_normalize_findings_accepts_typeddict_or_plain_dict() -> None:
    """NormalizedFinding (TypedDict) is documentation-shape only — the
    runtime functions accept plain dicts. This locks the contract.
    """
    nf: NormalizedFinding = {
        "tool": "aegisgraph",
        "target": "signal",
        "category": "deeplink-open-redirect",
        "rule_id": "INV-11",
        "location_hash": "loc-x",
        "severity": "warning",
    }
    matrix = compute_overlap_matrix(findings=[dict(nf)])
    assert matrix["signal"]["deeplink-open-redirect"]["tool_counts"]["aegisgraph"] == 1
