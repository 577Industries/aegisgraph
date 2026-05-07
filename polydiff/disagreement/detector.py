"""Disagreement detector. Pairwise + cluster-by-axis passes.

The v2 fact vector treats `null` as "no opinion." Axes where any
parser reports `null` are excluded from comparison against that
parser; that prevents the orchestrator from fabricating disagreements
the parsers themselves did not observe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# Axes the detector compares. Drawn from the v2 schema; includes the
# v1 axes for backwards compatibility plus the new SR-relevant ones.
COMPARABLE_AXES: tuple[str, ...] = (
    "scheme",
    "scheme_lowercased",
    "host",
    "host_lowercased",
    "host_decoded",
    "host_is_ip_literal",
    "host_is_ipv4",
    "host_is_ipv6",
    "host_is_loopback",
    "host_is_private_or_link_local",
    "host_has_idn",
    "host_punycode",
    "port",
    "port_value",
    "path",
    "path_normalized",
    "path_traversal_resolved",
    "userinfo_present",
    "userinfo_raw",
    "username",
    "password_present",
    "percent_decoding_applied_in_host",
    "percent_decoding_applied_in_path",
    "trailing_slash_normalized",
    "leading_zeroes_in_octets_stripped",
    "tab_or_newline_stripped",
    "backslash_treated_as_slash",
    "control_chars_in_host_rejected",
    "scheme_authority_separator_strict",
    "parsed",
    "parse_error",
)


@dataclass(frozen=True)
class Disagreement:
    input_id: str
    axis: str
    parser_values: dict[str, Any]
    security_tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_id": self.input_id,
            "axis": self.axis,
            "parser_values": dict(self.parser_values),
            "security_tags": list(self.security_tags),
        }


def _axis_value(vector: dict[str, Any], axis: str) -> Any:
    return vector.get(axis)


def _is_no_opinion(value: Any) -> bool:
    return value is None


def detect(vectors: list[dict[str, Any]], security_tags_for=None) -> list[Disagreement]:
    """Return all disagreements across `vectors`.

    `vectors` is a list of v2 fact-vectors that share the same `input_id`.
    `security_tags_for(axis, values_set)` is an optional callable that
    returns a list of security-relevance tags; if None, no tags are
    attached and the classifier can be applied later.
    """
    if not vectors:
        return []
    input_id = str(vectors[0].get("input_id", "<unknown>"))

    out: list[Disagreement] = []
    for axis in COMPARABLE_AXES:
        # Per-parser opinions, dropping null ("no opinion").
        values: dict[str, Any] = {}
        for v in vectors:
            profile = v.get("parser_profile", "unknown")
            val = _axis_value(v, axis)
            if not _is_no_opinion(val):
                values[profile] = val

        if len({_freeze(v) for v in values.values()}) > 1:
            tags = security_tags_for(axis, set(values.values())) if security_tags_for else []
            out.append(
                Disagreement(
                    input_id=input_id,
                    axis=axis,
                    parser_values=values,
                    security_tags=list(tags),
                )
            )
    return out


def _freeze(v: Any) -> Any:
    """Return a hashable version of `v` for set comparison."""
    if isinstance(v, list):
        return tuple(_freeze(x) for x in v)
    if isinstance(v, dict):
        return tuple(sorted((k, _freeze(val)) for k, val in v.items()))
    return v


def axis_hotspots(disagreements: Iterable[Disagreement]) -> dict[str, int]:
    """Count of disagreements per axis (debug / triage view)."""
    counts: dict[str, int] = {}
    for d in disagreements:
        counts[d.axis] = counts.get(d.axis, 0) + 1
    return counts
