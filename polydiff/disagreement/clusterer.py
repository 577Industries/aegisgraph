"""Group Disagreement records by (axis, parser_pair, error-class).

Used by the triage view to deduplicate the firehose of Disagreement
records into a small set of cluster exemplars.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .detector import Disagreement


def _parser_pair_key(d: Disagreement) -> str:
    profiles = sorted(d.parser_values.keys())
    return "|".join(profiles)


def _error_class(d: Disagreement) -> str:
    """Coarse error class derived from the value set.

    Boolean axes get class "true_vs_false"; integer/string axes get
    "value_mismatch"; null-vs-non-null gets "opinion_vs_no_opinion".
    """
    values = list(d.parser_values.values())
    has_null = any(v is None for v in values)
    has_bool = any(isinstance(v, bool) for v in values)
    if has_bool and not has_null:
        truthy = sum(1 for v in values if v is True)
        falsy = sum(1 for v in values if v is False)
        if truthy and falsy:
            return "true_vs_false"
    if has_null:
        return "opinion_vs_no_opinion"
    return "value_mismatch"


def cluster(
    disagreements: Iterable[Disagreement],
) -> dict[tuple[str, str, str], list[Disagreement]]:
    """Group disagreements by (axis, parser_pair, error_class)."""
    out: dict[tuple[str, str, str], list[Disagreement]] = defaultdict(list)
    for d in disagreements:
        key = (d.axis, _parser_pair_key(d), _error_class(d))
        out[key].append(d)
    return dict(out)


def cluster_summary(
    clusters: dict[tuple[str, str, str], list[Disagreement]]
) -> list[dict[str, object]]:
    """Flatten cluster dict into a list of summary records."""
    summary: list[dict[str, object]] = []
    for (axis, pair, err_class), bucket in sorted(clusters.items()):
        summary.append({
            "axis": axis,
            "parser_pair": pair,
            "error_class": err_class,
            "count": len(bucket),
            "exemplar_input_ids": sorted({d.input_id for d in bucket})[:5],
        })
    return summary
