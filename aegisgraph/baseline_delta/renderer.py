"""Renderer for the baseline-tool delta report.

Input: a list of normalized findings shaped like:

    {
      "tool":          "codeql" | "semgrep" | "mobsf" | "aegisgraph",
      "target":        "signal" | "element-x",
      "target_id":     "signal_android@1043851" | "elementx_android@91d265e6",
      "category":      <slug>,
      "rule_id":       <tool-specific rule id>,
      "location_hash": <16-hex-char digest of (path, line)>,
      "severity":      "error" | "warning" | "note" | "none",
    }

Outputs (pure functional, no I/O in this module):
  * `compute_overlap_matrix(findings=...)` -> nested dict structure
    keyed by [target][category] with per-tool counts and a
    `shared_locations` list of `{location_hash, tools}` rows where two
    or more tools coincide on the same `(category, location_hash)`.
  * `compute_added_by_aegisgraph(findings=...)` -> nested dict structure
    keyed by [target][category] with the count of AG-only locations
    in that cell.
  * `render_delta_report_markdown(report_payload=...)` -> str — used by
    the orchestrator to write `delta-report.md`.
  * `build_delta_report_payload(...)` -> dict — used by the
    orchestrator to write `delta-report.json`.

These functions are designed to operate on hand-rolled test fixtures
without any environment dependency.
"""

from __future__ import annotations

from typing import Any, Iterable, TypedDict

from ..constants import STATIC_GENERATED_AT


class NormalizedFinding(TypedDict):
    """Documentation-shape TypedDict — runtime functions accept plain
    `dict[str, Any]`. The TypedDict exists so static type checkers and
    reviewers can see the contract.
    """

    tool: str
    target: str
    category: str
    rule_id: str
    location_hash: str
    severity: str


_NON_AG_TOOLS = frozenset({"codeql", "semgrep", "mobsf"})
_ALL_TOOLS = ("codeql", "semgrep", "mobsf", "aegisgraph")


def _per_target_categories(
    findings: Iterable[dict[str, Any]],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Group findings by target -> category -> [findings...]."""
    bucket: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for f in findings:
        target = str(f["target"])
        category = str(f["category"])
        bucket.setdefault(target, {}).setdefault(category, []).append(dict(f))
    return bucket


def compute_overlap_matrix(
    *,
    findings: Iterable[dict[str, Any]],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Compute the per-target × per-category × per-tool overlap matrix.

    Returns:
        {
          target: {
            category: {
              "tool_counts": {tool: int, ...},   # how many findings per tool
              "shared_locations": [
                 {"location_hash": "...", "tools": ["codeql", "semgrep"]},
                 ...
              ],
            },
            ...
          },
          ...
        }
    """
    grouped = _per_target_categories(findings)
    matrix: dict[str, dict[str, dict[str, Any]]] = {}
    for target, by_cat in grouped.items():
        matrix[target] = {}
        for category, rows in by_cat.items():
            tool_counts: dict[str, int] = {}
            # location_hash -> set of tools at that location
            loc_to_tools: dict[str, set[str]] = {}
            for row in rows:
                tool = str(row["tool"])
                loc = str(row["location_hash"])
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
                loc_to_tools.setdefault(loc, set()).add(tool)
            shared_locations = [
                {
                    "location_hash": loc,
                    "tools": sorted(tools),
                }
                for loc, tools in loc_to_tools.items()
                if len(tools) >= 2
            ]
            # Stable sort by location_hash for determinism.
            shared_locations.sort(key=lambda r: r["location_hash"])
            matrix[target][category] = {
                "tool_counts": tool_counts,
                "shared_locations": shared_locations,
            }
    return matrix


def compute_added_by_aegisgraph(
    *,
    findings: Iterable[dict[str, Any]],
) -> dict[str, dict[str, int]]:
    """Count AG-only locations per (target, category).

    A location is "AG-only" if at least one finding at that
    `(target, category, location_hash)` triple has tool=aegisgraph
    AND no finding at that triple has tool in {codeql, semgrep, mobsf}.

    Returns a nested dict {target: {category: int}}. Categories with no
    AG findings are omitted; targets with no AG findings are omitted.
    """
    grouped = _per_target_categories(findings)
    delta: dict[str, dict[str, int]] = {}
    for target, by_cat in grouped.items():
        for category, rows in by_cat.items():
            # Per (location_hash) collect which tools reported
            loc_to_tools: dict[str, set[str]] = {}
            for row in rows:
                loc = str(row["location_hash"])
                tool = str(row["tool"])
                loc_to_tools.setdefault(loc, set()).add(tool)
            ag_only_count = sum(
                1
                for tools in loc_to_tools.values()
                if "aegisgraph" in tools and tools.isdisjoint(_NON_AG_TOOLS)
            )
            # Emit every (target, category) cell the findings list
            # produced so callers can index by name without KeyError.
            # When AG had no findings at all in this cell the value is
            # 0; when AG had findings but a baseline also covers the
            # same location_hash the value is also 0; the M14 metric
            # is the >0 cells.
            delta.setdefault(target, {})[category] = ag_only_count
    return delta


def build_delta_report_payload(
    *,
    findings: Iterable[dict[str, Any]],
    per_tool_envelopes: dict[str, dict[str, list[dict[str, Any]]]],
    target_metadata: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build the machine-readable delta-report.json payload.

    Args:
        findings: flat list of normalized findings (all tools, all
                  targets).
        per_tool_envelopes: nested dict
            {target_key: {tool: envelope_dict_from_runner, ...}}
            keyed exactly as the per-target output directory tree.
        target_metadata: nested dict
            {target_key: {repo_url, commit, name, target_id}}
            for the report header.

    Returns:
        A JSON-serializable dict.
    """
    findings_list = list(findings)
    matrix = compute_overlap_matrix(findings=findings_list)
    added_by_ag = compute_added_by_aegisgraph(findings=findings_list)

    # Per-target × per-tool summary counts (rolls up to the markdown
    # report's headline table)
    per_target_summary: dict[str, dict[str, Any]] = {}
    for target_key, by_tool in per_tool_envelopes.items():
        tool_rows: dict[str, dict[str, Any]] = {}
        for tool, env in by_tool.items():
            tool_rows[tool] = {
                "status": env.get("status"),
                "findings_count": env.get("findings_count", 0),
                "reason": env.get("reason", ""),
                "tool_version": env.get("tool_version"),
            }
        per_target_summary[target_key] = {
            "metadata": target_metadata.get(target_key, {}),
            "tools": tool_rows,
            "categories": sorted(matrix.get(target_key, {}).keys()),
            "added_by_aegisgraph_total": sum(added_by_ag.get(target_key, {}).values()),
        }

    return {
        "tool_output_type": "baseline_tool_delta_report",
        "version": "v1.0",
        "generated_at": STATIC_GENERATED_AT,
        "generated_by": "aegisgraph-tier3-research",
        # sanitize_check Rule 4: tool_output_type documents staged under
        # the proposal package must declare sanitized_candidate. The
        # payload here contains only rule_ids + location_hashes + per
        # tool counts — no snippets, no vendor contacts — so the
        # marking is accurate.
        "safety_posture": "sanitized_candidate",
        "milestone": "M14",
        "deliverable": "baseline-tool-delta-report",
        "tools_compared": list(_ALL_TOOLS),
        "per_target_summary": per_target_summary,
        "overlap_matrix": matrix,
        "added_by_aegisgraph": added_by_ag,
        "findings_total": len(findings_list),
    }


def render_delta_report_markdown(*, report_payload: dict[str, Any]) -> str:
    """Render the human-readable `delta-report.md`.

    The markdown is intentionally minimal — header tables, per-target
    overlap matrices, and the added-by-AegisGraph delta column. No
    SARIF excerpts or source snippets (Rule 8).
    """
    out: list[str] = []
    out.append("# Baseline-tool delta report (AegisGraph vs CodeQL / Semgrep / MobSF)")
    out.append("")
    out.append(f"_Generated at:_ `{report_payload['generated_at']}`")
    out.append(f"_Milestone:_ {report_payload['milestone']}")
    out.append("")
    out.append("## What this report measures")
    out.append("")
    out.append(
        "For each pinned Secure Messenger App (Signal Android, Element X "
        "Android), this report contrasts findings from three single-tool "
        "baselines (CodeQL alone, Semgrep alone, MobSF alone) against "
        "AegisGraph (15-invariant InvariantCheck library v3 + PolyDiff "
        "Extended regression). The headline metric is the **\"added by "
        "AegisGraph\"** column: findings present in AegisGraph output AND "
        "absent in (codeql ∪ semgrep ∪ mobsf) at the same "
        "`(category, location_hash)` coordinate. This is the M14 "
        "discovery-delta metric per Phase II plan §5."
    )
    out.append("")
    out.append("## Per-target summary")
    out.append("")

    summary = report_payload.get("per_target_summary", {})
    for target_key, per_target in sorted(summary.items()):
        md = per_target.get("metadata") or {}
        out.append(f"### {md.get('name') or target_key}")
        out.append("")
        out.append(f"- target_id: `{md.get('target_id', '?')}`")
        out.append(f"- repo: {md.get('repo_url', '?')}")
        out.append(f"- commit: `{md.get('commit', '?')}`")
        out.append("")
        out.append("| Tool | Status | Findings | Tool version | Reason |")
        out.append("|---|---|---|---|---|")
        for tool in _ALL_TOOLS:
            row = per_target.get("tools", {}).get(tool, {})
            status = row.get("status") or "(not run)"
            count = row.get("findings_count", 0)
            ver = row.get("tool_version") or "_n/a_"
            reason = (row.get("reason") or "").replace("|", "/").replace("\n", " ")
            out.append(f"| {tool} | `{status}` | {count} | `{ver}` | {reason} |")
        out.append("")
        added = per_target.get("added_by_aegisgraph_total", 0)
        out.append(f"**Added by AegisGraph (this target):** {added}")
        out.append("")

    out.append("## Overlap matrix (per-category)")
    out.append("")
    out.append(
        "Cells are `(category × tool)`. The 'shared' column lists how "
        "many `(category, location_hash)` coordinates have two or more "
        "tools reporting at the same spot — these are deduplicated "
        "overlaps, NOT independent findings."
    )
    out.append("")

    overlap = report_payload.get("overlap_matrix", {})
    for target_key, by_cat in sorted(overlap.items()):
        out.append(f"### {target_key}")
        out.append("")
        out.append("| Category | CodeQL | Semgrep | MobSF | AegisGraph | Shared locations |")
        out.append("|---|---|---|---|---|---|")
        for category in sorted(by_cat.keys()):
            row = by_cat[category]
            tc = row.get("tool_counts", {})
            shared = len(row.get("shared_locations", []))
            out.append(
                f"| {category} | {tc.get('codeql', 0)} | {tc.get('semgrep', 0)} "
                f"| {tc.get('mobsf', 0)} | {tc.get('aegisgraph', 0)} | {shared} |"
            )
        out.append("")

    out.append("## Added by AegisGraph (per-target, per-category)")
    out.append("")
    out.append(
        "Counts the `(target, category, location_hash)` coordinates where "
        "AegisGraph reports a finding AND none of CodeQL / Semgrep / "
        "MobSF report at the same coordinate. This is the discovery-delta "
        "column for the M14 demo."
    )
    out.append("")
    added = report_payload.get("added_by_aegisgraph", {})
    for target_key in sorted(added.keys()):
        cats = added[target_key]
        out.append(f"### {target_key}")
        out.append("")
        out.append("| Category | Added by AegisGraph |")
        out.append("|---|---|")
        for category in sorted(cats.keys()):
            out.append(f"| {category} | {cats[category]} |")
        out.append("")

    out.append("## Constraints and caveats")
    out.append("")
    out.append(
        "- **Anchor-only**: target source trees are pinned by commit "
        "hash and not redistributed in this research repo. The "
        "self-hosted runner clones them at execution time per "
        "`extraction/targets/<target>/build_db.sh`."
    )
    out.append(
        "- **MobSF transparency**: when no APK is available the "
        "`mobsf` row reports `apk_missing` and a sibling "
        "`MOBSF-LIMITED.md` records the limitation. No fabricated "
        "findings."
    )
    out.append(
        "- **Sanitize-check Rule 7/8/9**: every emitted record passes "
        "through `aegisgraph.evidence.finalize_record` (for AG records) "
        "or the sanitization projection here (for baseline tools). "
        "Source snippets are NEVER carried into the report; only "
        "`location_hash` fingerprints are."
    )
    return "\n".join(out) + "\n"


__all__ = [
    "NormalizedFinding",
    "compute_overlap_matrix",
    "compute_added_by_aegisgraph",
    "build_delta_report_payload",
    "render_delta_report_markdown",
]
