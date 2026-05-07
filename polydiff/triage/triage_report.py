"""CLI/HTML triage view for PolyDiff Findings.

The report is a structured summary that the operator reviews before any
Disagreement is promoted to a Finding in the AegisGraph evidence tree.
Implements the deduplication + viewer described in SPEC §5.9 at a level
appropriate for the current stream (CLI table; HTML deferred).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable

from ..disagreement.detector import Disagreement
from ..disagreement.clusterer import cluster, cluster_summary


@dataclass
class TriageRow:
    cluster_id: str
    axis: str
    parser_pair: str
    error_class: str
    count: int
    security_tags: list[str]
    exemplar_input_ids: list[str]


def build(disagreements: Iterable[Disagreement]) -> list[TriageRow]:
    """Build triage rows by clustering disagreements."""
    by_cluster = cluster(disagreements)
    rows: list[TriageRow] = []
    for (axis, pair, err_class), bucket in sorted(by_cluster.items()):
        # Union security_tags across the bucket.
        tags: list[str] = []
        seen: set[str] = set()
        for d in bucket:
            for t in d.security_tags:
                if t not in seen:
                    tags.append(t)
                    seen.add(t)
        rows.append(TriageRow(
            cluster_id=f"{axis}|{pair}|{err_class}",
            axis=axis,
            parser_pair=pair,
            error_class=err_class,
            count=len(bucket),
            security_tags=tags,
            exemplar_input_ids=sorted({d.input_id for d in bucket})[:5],
        ))
    return rows


def to_text(rows: list[TriageRow]) -> str:
    """Render rows as a human-readable text table."""
    if not rows:
        return "No disagreements to triage.\n"
    lines = []
    lines.append(f"{'AXIS':<35}{'PAIR':<55}{'CLASS':<25}{'N':<5}TAGS")
    lines.append("-" * 140)
    for r in rows:
        lines.append(
            f"{r.axis[:34]:<35}{r.parser_pair[:54]:<55}{r.error_class[:24]:<25}{r.count:<5}"
            f"{','.join(r.security_tags)}"
        )
    return "\n".join(lines) + "\n"


def to_json(rows: list[TriageRow]) -> str:
    return json.dumps(
        {"clusters": [r.__dict__ for r in rows]},
        indent=2,
        sort_keys=True,
    )


__all__ = ["TriageRow", "build", "to_text", "to_json"]
