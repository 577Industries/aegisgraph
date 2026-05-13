"""Generic disagreement classification / triage.

Hosts the `Disagreement` dataclass and `detect_disagreements()` —
both family-agnostic. Family-specific rules live alongside the
family in `aegisgraph/polydiff/families/<family>/` and plug into
`detect_disagreements` via the `rules_loader` parameter.

Extracted from the monolithic `aegisgraph/polydiff.py` as part of
T-M2.3 (PolyDiff URL family refactor).

T-M2.1 (this commit) extends the module ADDITIVELY with image-family
triage classification (`classify_image_disagreement`). The URL family
detection path is unchanged.
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


# ---------------------------------------------------------------------------
# Image-family triage (T-M2.1)
# ---------------------------------------------------------------------------
#
# Per Asemarefactor.md lines 87-93 (Engine 1 canonical image-family example):
#
#   decode_outcome divergence, one ok + one crash     -> HIGH
#       Memory-corruption suspect (libwebp CVE-2023-4863 class).
#   color_space profile divergence with same pixels   -> LOW
#       Metadata interpretation; no security signal.
#   dimensions divergence                              -> MEDIUM
#       Integer-overflow suspect in dimension parsing.
#   first_pixel_rgba divergence with same dimensions   -> MEDIUM
#       Color-channel handling bug.
#   frame_count divergence in animated images          -> MEDIUM-HIGH
#       Parser state-machine deviation (libwebp class).
#
# The rules are ADDITIVE — they do not touch URL-family detection. The image
# regression module calls `classify_image_disagreement(fact_vector_diff)` to
# stamp each emitted AG-DIS-IMG-* record with `triage_class` + rationale.

_TRIAGE_PRIORITY = {
    "HIGH": 4,
    "MEDIUM-HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NOISE": 0,
}


def classify_image_disagreement(fact_vector_diff: dict[str, Any]) -> dict[str, str]:
    """Map an image-family `fact_vector_diff` to a triage class + rationale.

    `fact_vector_diff` keys are axis names (e.g. "decode_outcome",
    "dimensions"); values are arrays of per-implementation observations.
    For each axis we evaluate the divergence shape and assign a triage
    label. If the diff touches multiple axes the final label is the most
    severe of the per-axis labels (priority HIGH > MEDIUM-HIGH > MEDIUM >
    LOW > NOISE).

    Returns: {"triage_class": str, "triage_rationale": str}

    Raises: never. Unknown axes contribute NOISE and a generic rationale.
    """
    if not isinstance(fact_vector_diff, dict) or not fact_vector_diff:
        return {
            "triage_class": "NOISE",
            "triage_rationale": "empty disagreement",
        }

    per_axis: list[tuple[str, str, str]] = []  # (axis, class, rationale)

    for axis, values in fact_vector_diff.items():
        cls, rationale = _classify_image_axis(axis, values, fact_vector_diff)
        per_axis.append((axis, cls, rationale))

    # Pick the worst (highest-priority) per-axis label.
    per_axis.sort(key=lambda t: _TRIAGE_PRIORITY.get(t[1], 0), reverse=True)
    top_axis, top_class, top_rationale = per_axis[0]
    return {
        "triage_class": top_class,
        "triage_rationale": top_rationale,
    }


def _classify_image_axis(
    axis: str, values: Any, full_diff: dict[str, Any]
) -> tuple[str, str]:
    """Per-axis triage logic. Returns (triage_class, rationale)."""
    if axis == "decode_outcome":
        return _classify_decode_outcome(values)
    if axis == "frame_count":
        return (
            "MEDIUM-HIGH",
            "frame-count parser-state divergence (libwebp class)",
        )
    if axis == "dimensions":
        return (
            "MEDIUM",
            "dimensions divergence — integer-overflow suspect in dimension parsing",
        )
    if axis == "first_pixel_rgba":
        # If dimensions agree, this is a color-channel bug, not a layout bug.
        if "dimensions" not in full_diff:
            return (
                "MEDIUM",
                "pixel divergence with same dimensions — color-channel handling bug",
            )
        return ("LOW", "pixel divergence with dimensions divergence — likely cascade")
    if axis == "color_space":
        # Same-pixels color-space divergence is the LOW noise channel; we
        # detect "same pixels" as first_pixel_rgba NOT being in the diff.
        if "first_pixel_rgba" not in full_diff:
            return (
                "LOW",
                "color-space profile divergence with same pixels — metadata interpretation difference",
            )
        return (
            "MEDIUM",
            "color-space divergence with pixel divergence — color-pipeline bug",
        )
    if axis == "alpha_premultiplied":
        return ("LOW", "alpha-premultiplication interpretation difference")
    if axis == "parser_warnings":
        return ("NOISE", "warnings-only divergence")
    # Unknown axis: fall back to NOISE so a future schema addition cannot
    # accidentally promote a benign axis to HIGH.
    return ("NOISE", f"unknown image-family axis {axis!r}")


def _classify_decode_outcome(values: Any) -> tuple[str, str]:
    """Decode_outcome triage: one_crash_one_ok -> HIGH."""
    if not isinstance(values, list) or len(values) < 2:
        return ("NOISE", "decode_outcome with <2 observations")

    statuses: list[str] = []
    for v in values:
        if isinstance(v, dict):
            statuses.append(str(v.get("status", "")))
        else:
            statuses.append(str(v))

    has_ok = any(s == "ok" for s in statuses)
    has_crash = any(s == "crash" for s in statuses)
    has_oom = any(s == "oom" for s in statuses)
    has_decode_error = any(s == "decode_error" for s in statuses)

    if has_ok and has_crash:
        return (
            "HIGH",
            "decode_outcome divergence (one ok, one crash) — memory corruption suspect",
        )
    if has_ok and has_oom:
        return (
            "MEDIUM-HIGH",
            "decode_outcome divergence (one ok, one oom) — allocator-bounds suspect",
        )
    if has_ok and has_decode_error:
        return (
            "MEDIUM",
            "decode_outcome divergence (one ok, one decode_error) — parser acceptance mismatch",
        )
    if has_crash and has_decode_error:
        return (
            "MEDIUM-HIGH",
            "decode_outcome divergence (one crash, one decode_error) — parser robustness gap",
        )
    if has_crash and has_oom:
        return (
            "MEDIUM",
            "decode_outcome divergence (crash vs oom) — resource-handling divergence",
        )
    return ("LOW", "decode_outcome divergence without ok/crash pairing")


__all__ = [
    "Disagreement",
    "detect_disagreements",
    "classify_image_disagreement",
]
