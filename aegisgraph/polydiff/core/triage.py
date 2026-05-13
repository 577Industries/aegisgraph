"""Generic disagreement classification / triage.

Hosts the `Disagreement` dataclass and `detect_disagreements()` —
both family-agnostic. Family-specific rules live alongside the
family in `aegisgraph/polydiff/families/<family>/` and plug into
`detect_disagreements` via the `rules_loader` parameter.

Extracted from the monolithic `aegisgraph/polydiff.py` as part of
T-M2.3 (PolyDiff URL family refactor). Pure refactor — no behavior
change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Disagreement:
    """Backwards-compatible Disagreement type used by tests + cli."""

    input_id: str
    axis: str
    parser_values: dict[str, Any]
    security_tags: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_id": self.input_id,
            "axis": self.axis,
            "parser_values": dict(self.parser_values),
            "security_tags": list(self.security_tags),
        }


def detect_disagreements(
    vectors: list[dict[str, Any]], rules_loader=None
) -> list[Disagreement]:
    """Backwards-compat wrapper around polydiff.disagreement.detect.

    Accepts an optional `rules_loader` callable returning a list of
    triage rules; defaults to loading from polydiff/triage/rules.yml.
    """
    from polydiff.disagreement.detector import detect as _detect
    from polydiff.triage.classifier import classify, load_rules

    rules = rules_loader() if rules_loader else load_rules()

    def security_tags_for(axis: str, values: set[Any]) -> list[str]:
        return classify(axis, values, rules=rules)

    raw = _detect(vectors, security_tags_for=security_tags_for)
    return [
        Disagreement(
            input_id=d.input_id,
            axis=d.axis,
            parser_values=d.parser_values,
            security_tags=d.security_tags,
        )
        for d in raw
    ]


__all__ = ["Disagreement", "detect_disagreements"]
