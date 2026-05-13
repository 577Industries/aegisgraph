"""`aegisgraph workbench list` — engine/target/claim-state filtered listing."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .filters import FindingFilters
from .registry import FindingRow, scan


def list_findings(root: Path, filters: FindingFilters | None = None) -> list[dict[str, Any]]:
    """Return filtered finding rows.

    Each row dict carries the fields surfaced by `--format table` and
    `--format json`. The full record envelope is attached as `_record`
    so callers can drill into evidence_refs / score_vector without a
    second disk read.

    Sorted by score_total descending, then by record_id ascending for
    stable output.
    """
    flat = scan(root)
    flt = filters or FindingFilters()
    rows = [row.to_row_dict() for row in flat]
    matched = [row for row in rows if flt.matches(row)]
    matched.sort(key=lambda r: (-r.get("score_total", 0.0), r.get("record_id", "")))
    return matched


def render_table(rows: list[dict[str, Any]]) -> str:
    """ASCII table renderer (no rich.live). Stable column widths.

    Columns: record_id | engine | claim_state | score | target.

    Intentionally simple; the workbench is a static CLI — rich tables
    are allowed but `rich.live` (and any TUI surface) is forbidden by
    test_no_tui_imports.py.
    """
    if not rows:
        return "(no findings)\n"
    columns = ("record_id", "engine", "claim_state", "score", "target")
    column_data: list[list[str]] = []
    for row in rows:
        target = _target_str(row.get("target") or row.get("target_id"))
        column_data.append(
            [
                str(row.get("record_id", "")),
                str(row.get("engine", "")),
                str(row.get("claim_state", "")),
                f"{float(row.get('score_total') or 0.0):.3f}",
                target,
            ]
        )
    widths = [
        max(len(columns[i]), max((len(r[i]) for r in column_data), default=0))
        for i in range(len(columns))
    ]
    header = " | ".join(columns[i].ljust(widths[i]) for i in range(len(columns)))
    sep = "-+-".join("-" * widths[i] for i in range(len(columns)))
    body = "\n".join(
        " | ".join(r[i].ljust(widths[i]) for i in range(len(columns)))
        for r in column_data
    )
    return f"{header}\n{sep}\n{body}\n"


def _target_str(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or value.get("repo_url") or "")
    if isinstance(value, str):
        return value
    return ""
