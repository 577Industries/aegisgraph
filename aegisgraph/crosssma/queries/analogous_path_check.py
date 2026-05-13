"""analogous_path_check: does target X have a graph path matching this shape?

v0 implementation reads `extraction/output/<graph_dir>/graph.json`
when available and answers a coarse question: does the graph contain
ANY edge whose relationship hints at the requested path class?

If no extraction output exists for the target, the query returns
`AnalogousPathResult(present=None, ...)` to signal unknown rather
than False. The matrix renderer treats unknown the same way as
dependency_absent for v0 (we don't fabricate evidence).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aegisgraph.crosssma.target_registry import Target
from aegisgraph.io import load_json, repo_root


_TARGET_TO_GRAPH_DIR = {
    "signal-android": "signal",
    "element-x-android": "element-x",
}


@dataclass(frozen=True)
class AnalogousPathResult:
    target_id: str
    path_class: str
    present: bool | None
    matched_edges: int


def _graph_path_for(target: Target, root: Path | None = None) -> Path | None:
    base = root or repo_root()
    graph_dir = _TARGET_TO_GRAPH_DIR.get(target.target_id)
    if not graph_dir:
        return None
    candidate = base / "extraction" / "output" / graph_dir / "graph.json"
    if not candidate.exists():
        return None
    return candidate


def check_analogous_path(
    target: Target, path_class: str, root: Path | None = None
) -> AnalogousPathResult:
    graph_path = _graph_path_for(target, root)
    if graph_path is None:
        return AnalogousPathResult(
            target_id=target.target_id,
            path_class=path_class,
            present=None,
            matched_edges=0,
        )
    try:
        graph = load_json(graph_path)
    except (OSError, ValueError):
        return AnalogousPathResult(
            target_id=target.target_id,
            path_class=path_class,
            present=None,
            matched_edges=0,
        )
    edges = graph.get("edges", []) if isinstance(graph, dict) else []
    # Match relationship strings containing the path-class tokens.
    needle = path_class.lower().replace("_", "")
    count = 0
    for edge in edges:
        rel = str(edge.get("relationship", "")).lower().replace("_", "")
        if needle and needle in rel:
            count += 1
    return AnalogousPathResult(
        target_id=target.target_id,
        path_class=path_class,
        present=count > 0,
        matched_edges=count,
    )


__all__ = ["AnalogousPathResult", "check_analogous_path"]
