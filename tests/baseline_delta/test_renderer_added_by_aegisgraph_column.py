"""The "added by AegisGraph" delta column.

A finding is "added by AegisGraph" if it appears in the AegisGraph
output AND no other tool (codeql ∪ semgrep ∪ mobsf) reports a finding
at the same (target, category, location_hash). This is the M14
discovery-delta metric: it quantifies what AegisGraph surfaces that
single-tool baselines miss.

Tested behaviors:
  * AG-only finding -> added_by_aegisgraph = 1 for that cell
  * AG + CodeQL at same location -> added_by_aegisgraph = 0
  * AG at one location, CodeQL at a different location, same category
    -> added_by_aegisgraph = 1 (different locations, AG-unique)
  * Non-AG-only findings (e.g. CodeQL alone) NEVER count toward
    added_by_aegisgraph (must be zero in those rows)
  * The delta is computed per-target.
"""

from __future__ import annotations

from aegisgraph.baseline_delta.renderer import (
    compute_added_by_aegisgraph,
    compute_overlap_matrix,
)


def _finding(tool: str, target: str, category: str, loc: str, rule: str = "r") -> dict:
    return {
        "tool": tool,
        "target": target,
        "category": category,
        "rule_id": rule,
        "location_hash": loc,
        "severity": "warning",
    }


def test_added_by_aegisgraph_when_only_ag_reports_a_location() -> None:
    findings = [
        _finding("aegisgraph", "signal", "url-fetch-no-policy", "loc-001", "AG-IV-01"),
    ]
    delta = compute_added_by_aegisgraph(findings=findings)
    assert delta["signal"]["url-fetch-no-policy"] == 1


def test_added_by_aegisgraph_zero_when_codeql_reports_same_location() -> None:
    findings = [
        _finding("aegisgraph", "signal", "url-fetch-no-policy", "loc-001", "AG-IV-01"),
        _finding("codeql", "signal", "url-fetch-no-policy", "loc-001", "codeql-rule-1"),
    ]
    delta = compute_added_by_aegisgraph(findings=findings)
    assert delta["signal"]["url-fetch-no-policy"] == 0


def test_added_by_aegisgraph_counts_different_locations_separately() -> None:
    """AG reports two locations; CodeQL reports one of them; the
    second AG location remains AG-only.
    """
    findings = [
        _finding("aegisgraph", "signal", "url-fetch-no-policy", "loc-A", "AG-IV-01a"),
        _finding("aegisgraph", "signal", "url-fetch-no-policy", "loc-B", "AG-IV-01b"),
        _finding("codeql", "signal", "url-fetch-no-policy", "loc-A", "ql-1"),
    ]
    delta = compute_added_by_aegisgraph(findings=findings)
    assert delta["signal"]["url-fetch-no-policy"] == 1


def test_added_by_aegisgraph_ignores_semgrep_overlap_same_as_codeql() -> None:
    findings = [
        _finding("aegisgraph", "signal", "url-fetch-no-policy", "loc-001"),
        _finding("semgrep", "signal", "url-fetch-no-policy", "loc-001"),
    ]
    delta = compute_added_by_aegisgraph(findings=findings)
    assert delta["signal"]["url-fetch-no-policy"] == 0


def test_added_by_aegisgraph_ignores_mobsf_overlap() -> None:
    findings = [
        _finding("aegisgraph", "signal", "url-fetch-no-policy", "loc-001"),
        _finding("mobsf", "signal", "url-fetch-no-policy", "loc-001"),
    ]
    delta = compute_added_by_aegisgraph(findings=findings)
    assert delta["signal"]["url-fetch-no-policy"] == 0


def test_added_by_aegisgraph_per_target_isolation() -> None:
    """Cross-target overlaps must NOT cancel out AG-only deltas. A
    Signal AG-only finding remains AG-only even if Element-X CodeQL
    reports the same (category, location_hash).
    """
    findings = [
        _finding("aegisgraph", "signal", "url-fetch-no-policy", "loc-001"),
        _finding("codeql", "element-x", "url-fetch-no-policy", "loc-001"),
    ]
    delta = compute_added_by_aegisgraph(findings=findings)
    assert delta["signal"]["url-fetch-no-policy"] == 1
    assert delta["element-x"]["url-fetch-no-policy"] == 0


def test_added_by_aegisgraph_consistent_with_overlap_matrix() -> None:
    """A category cell's added_by_aegisgraph value must equal the number
    of AG-tool locations in that cell minus the number of locations
    shared with any non-AG tool.
    """
    findings = [
        _finding("aegisgraph", "signal", "deeplink-open-redirect", "loc-1"),
        _finding("aegisgraph", "signal", "deeplink-open-redirect", "loc-2"),
        _finding("aegisgraph", "signal", "deeplink-open-redirect", "loc-3"),
        _finding("codeql", "signal", "deeplink-open-redirect", "loc-2"),
    ]
    matrix = compute_overlap_matrix(findings=findings)
    delta = compute_added_by_aegisgraph(findings=findings)

    ag_count = matrix["signal"]["deeplink-open-redirect"]["tool_counts"]["aegisgraph"]
    shared_with_other = sum(
        1
        for entry in matrix["signal"]["deeplink-open-redirect"]["shared_locations"]
        if "aegisgraph" in entry["tools"] and len(entry["tools"]) > 1
    )
    assert ag_count - shared_with_other == delta["signal"]["deeplink-open-redirect"]


def test_added_by_aegisgraph_handles_no_ag_findings_in_target() -> None:
    findings = [
        _finding("codeql", "signal", "url-fetch-no-policy", "loc-001"),
    ]
    delta = compute_added_by_aegisgraph(findings=findings)
    # No AG findings means delta has no entry for that target
    # (or has the category at 0). Both are acceptable as long as the
    # value is zero or absent.
    assert delta.get("signal", {}).get("url-fetch-no-policy", 0) == 0
