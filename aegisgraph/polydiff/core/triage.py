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


# ---------------------------------------------------------------------------
# Opengraph-family triage (T-M2.2)
# ---------------------------------------------------------------------------
#
# Per the T-M2.2 spec, the opengraph family classifies disagreements as:
#
#   decode_outcome divergence, one ok + one crash     -> HIGH
#       Parser crash potential — memory/stack handling suspect.
#   og_url divergence with same input                  -> MEDIUM-HIGH
#       Open-redirect / SSRF surface; downstream consumers diverge on
#       what URL the link preview points to (Facebook crawler vs WHATWG
#       URL class).
#   twitter_card_type / og_type divergence             -> MEDIUM
#       Semantic confusion bug class (player-card-vs-summary, etc.).
#   canonical_url vs og_url divergence                 -> MEDIUM
#       Link-preview-confusion class (Snyk-2022 URL-confusion extended
#       to embed metadata; downstream picks the wrong canonical URL).
#   title / description text divergence                -> LOW
#       Cosmetic; benign formatting/encoding choices.
#
# Rules are ADDITIVE — they do not touch URL or image family classifiers.
# The opengraph regression module calls
# `classify_opengraph_disagreement(fact_vector_diff)` to stamp each emitted
# AG-DIS-OG-* record with `triage_class` + rationale.


def classify_opengraph_disagreement(fact_vector_diff: dict[str, Any]) -> dict[str, str]:
    """Map an opengraph-family `fact_vector_diff` to triage class + rationale.

    `fact_vector_diff` keys are axis names (e.g. "og_url", "decode_outcome",
    "twitter_card_type"); values are arrays of per-implementation
    observations. For each axis we evaluate the divergence shape and assign
    a triage label. If the diff touches multiple axes the final label is
    the most severe of the per-axis labels (priority HIGH > MEDIUM-HIGH >
    MEDIUM > LOW > NOISE).

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
        cls, rationale = _classify_opengraph_axis(axis, values, fact_vector_diff)
        per_axis.append((axis, cls, rationale))

    # Pick the worst (highest-priority) per-axis label.
    per_axis.sort(key=lambda t: _TRIAGE_PRIORITY.get(t[1], 0), reverse=True)
    _top_axis, top_class, top_rationale = per_axis[0]
    return {
        "triage_class": top_class,
        "triage_rationale": top_rationale,
    }


def _classify_opengraph_axis(
    axis: str, values: Any, full_diff: dict[str, Any]
) -> tuple[str, str]:
    """Per-axis triage logic for the opengraph family.

    Returns (triage_class, rationale).
    """
    if axis == "decode_outcome":
        # Reuse the image-family decode_outcome classifier; the rule is
        # family-agnostic (one_crash_one_ok -> HIGH).
        return _classify_decode_outcome(values)
    if axis == "og_url":
        return (
            "MEDIUM-HIGH",
            "og_url divergence — open-redirect / SSRF surface "
            "(downstream consumers resolve same input to different URLs)",
        )
    if axis == "twitter_card_type":
        return (
            "MEDIUM",
            "twitter_card_type divergence — semantic confusion bug class "
            "(card-type-divergence)",
        )
    if axis == "og_type":
        return (
            "MEDIUM",
            "og_type divergence — semantic confusion bug class "
            "(og-type-divergence)",
        )
    if axis == "canonical_url":
        return (
            "MEDIUM",
            "canonical_url divergence — link-preview-confusion class "
            "(Snyk-2022 URL-confusion extended to embed metadata)",
        )
    if axis == "og_image":
        return ("LOW", "og_image divergence — cosmetic image-url divergence")
    if axis == "twitter_image":
        return ("LOW", "twitter_image divergence — cosmetic image-url divergence")
    if axis == "og_title":
        return ("LOW", "og_title divergence — cosmetic text divergence")
    if axis == "og_video":
        return ("LOW", "og_video divergence — cosmetic video-url divergence")
    if axis == "oembed_type":
        return (
            "MEDIUM",
            "oembed_type divergence — provider-origin-confusion class",
        )
    if axis == "parser_warnings":
        return ("NOISE", "warnings-only divergence")
    # Unknown axis: fall back to NOISE so a future schema addition cannot
    # accidentally promote a benign axis to HIGH.
    return ("NOISE", f"unknown opengraph-family axis {axis!r}")


# ---------------------------------------------------------------------------
# Deeplink-family triage (T-M2.4)
# ---------------------------------------------------------------------------
#
# Per the T-M2.4 spec, the deeplink family classifies disagreements as:
#
#   decode_outcome divergence (one ok, one parse_error)        -> HIGH
#       Parser crash potential — one impl parsed cleanly while another
#       crashed/rejected the same input.
#   intent_action divergence                                   -> MEDIUM-HIGH
#       Android intent-confusion bug class — same URI, different Intent
#       action selected by Intent.parseUri vs the SMA's filters.
#   host or path divergence with same input                    -> MEDIUM
#       Parser inconsistency / redirect surface.
#   declared_permissions divergence                            -> MEDIUM
#       Android implicit-export surface — declared permission set diverges.
#   fragment_action divergence                                 -> MEDIUM
#       Fragment-encoded action divergence — link-handler may dispatch
#       differently.
#   query_params divergence                                    -> LOW
#       Query-string semantics often spec-tolerant.
#
# Rules are ADDITIVE — they do not touch URL, image, or opengraph family
# classifiers. The deeplink regression module calls
# `classify_deeplink_disagreement(fact_vector_diff)` to stamp each emitted
# AG-DIS-DL-* record with `triage_class` + rationale.


def classify_deeplink_disagreement(fact_vector_diff: dict[str, Any]) -> dict[str, str]:
    """Map a deeplink-family `fact_vector_diff` to triage class + rationale.

    `fact_vector_diff` keys are axis names (e.g. "intent_action",
    "decode_outcome", "host"); values are arrays of per-implementation
    observations. For each axis we evaluate the divergence shape and
    assign a triage label. If the diff touches multiple axes the final
    label is the most severe of the per-axis labels (priority HIGH >
    MEDIUM-HIGH > MEDIUM > LOW > NOISE).

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
        cls, rationale = _classify_deeplink_axis(axis, values, fact_vector_diff)
        per_axis.append((axis, cls, rationale))

    # Pick the worst (highest-priority) per-axis label.
    per_axis.sort(key=lambda t: _TRIAGE_PRIORITY.get(t[1], 0), reverse=True)
    _top_axis, top_class, top_rationale = per_axis[0]
    return {
        "triage_class": top_class,
        "triage_rationale": top_rationale,
    }


def _classify_deeplink_axis(
    axis: str, values: Any, full_diff: dict[str, Any]
) -> tuple[str, str]:
    """Per-axis triage logic for the deeplink family.

    Returns (triage_class, rationale).
    """
    if axis == "decode_outcome":
        return _classify_deeplink_decode_outcome(values)
    if axis == "intent_action":
        return (
            "MEDIUM-HIGH",
            "intent_action divergence — Android intent-confusion bug class "
            "(same URI parsed to different Intent action)",
        )
    if axis == "intent_category":
        return (
            "MEDIUM-HIGH",
            "intent_category divergence — Android intent-confusion bug class "
            "(same URI parsed to different Intent categories)",
        )
    if axis == "host":
        return (
            "MEDIUM",
            "host divergence — parser inconsistency / redirect surface "
            "(same input, different authority host)",
        )
    if axis == "path":
        return (
            "MEDIUM",
            "path divergence — parser inconsistency / traversal surface "
            "(same input, different resolved path)",
        )
    if axis == "declared_permissions":
        return (
            "MEDIUM",
            "declared_permissions divergence — Android implicit-export "
            "surface (declared permission set diverges)",
        )
    if axis == "fragment_action":
        return (
            "MEDIUM",
            "fragment_action divergence — link-handler may dispatch "
            "differently on fragment-encoded action",
        )
    if axis == "scheme":
        return (
            "MEDIUM",
            "scheme divergence — implementations recognized different URI "
            "schemes for the same input",
        )
    if axis == "query_params":
        return (
            "LOW",
            "query_params divergence — query-string semantics often "
            "spec-tolerant; cosmetic unless paired with host/path",
        )
    if axis == "parser_warnings":
        return ("NOISE", "warnings-only divergence")
    # Unknown axis: fall back to NOISE so a future schema addition cannot
    # accidentally promote a benign axis to HIGH.
    return ("NOISE", f"unknown deeplink-family axis {axis!r}")


def _classify_deeplink_decode_outcome(values: Any) -> tuple[str, str]:
    """Decode_outcome triage for the deeplink family.

    The deeplink fact-vector schema uses the status enum
    {ok, parse_error, scheme_unknown, malformed}. A one-ok-one-parse_error
    pairing is the canonical HIGH signal (one impl parsed cleanly while
    another crashed/rejected the same input — parser crash potential).
    """
    if not isinstance(values, list) or len(values) < 2:
        return ("NOISE", "decode_outcome with <2 observations")

    statuses: list[str] = []
    for v in values:
        if isinstance(v, dict):
            statuses.append(str(v.get("status", "")))
        else:
            statuses.append(str(v))

    has_ok = any(s == "ok" for s in statuses)
    has_parse_error = any(s == "parse_error" for s in statuses)
    has_scheme_unknown = any(s == "scheme_unknown" for s in statuses)
    has_malformed = any(s == "malformed" for s in statuses)

    if has_ok and has_parse_error:
        return (
            "HIGH",
            "decode_outcome divergence (one ok, one parse_error) — parser "
            "crash potential",
        )
    if has_ok and has_malformed:
        return (
            "MEDIUM-HIGH",
            "decode_outcome divergence (one ok, one malformed) — parser "
            "acceptance mismatch on syntactically-broken input",
        )
    if has_ok and has_scheme_unknown:
        return (
            "MEDIUM",
            "decode_outcome divergence (one ok, one scheme_unknown) — "
            "scheme-recognition disagreement",
        )
    if has_parse_error and has_malformed:
        return (
            "MEDIUM",
            "decode_outcome divergence (parse_error vs malformed) — parser "
            "robustness gap on the same input",
        )
    return ("LOW", "decode_outcome divergence without ok pairing")


# ---------------------------------------------------------------------------
# QR-family triage (T-M2.5)
# ---------------------------------------------------------------------------
#
# Per the T-M2.5 spec, the qr family classifies disagreements as:
#
#   decode_outcome divergence (one ok, one parse_error)        -> HIGH
#       Parser crash potential — one impl decoded cleanly while another
#       crashed/rejected the same input.
#   detected_text divergence with same input                   -> MEDIUM-HIGH
#       URL-in-QR phishing surface — same symbol, different decoded
#       text (e.g. iOS Camera URL handler vs ZXing extract diverge).
#   mode or encoding_charset divergence                        -> MEDIUM
#       Charset-confusion class — same symbol, different data mode
#       (byte vs kanji) or different charset (UTF-8 vs Shift-JIS).
#   structured_append (index|total) divergence                 -> MEDIUM
#       Multi-QR ordering bug class — structured-append pieces decoded
#       out of order.
#   ecc_level / version divergence                             -> LOW
#       Cosmetic — error-correction level / QR version reporting differs.
#
# Rules are ADDITIVE — they do not touch URL, image, opengraph, or
# deeplink family classifiers. The qr regression module calls
# `classify_qr_disagreement(fact_vector_diff)` to stamp each emitted
# AG-DIS-QR-* record with `triage_class` + rationale.


def classify_qr_disagreement(fact_vector_diff: dict[str, Any]) -> dict[str, str]:
    """Map a qr-family `fact_vector_diff` to triage class + rationale.

    `fact_vector_diff` keys are axis names (e.g. "detected_text",
    "decode_outcome", "mode"); values are arrays of per-implementation
    observations. For each axis we evaluate the divergence shape and
    assign a triage label. If the diff touches multiple axes the final
    label is the most severe of the per-axis labels (priority HIGH >
    MEDIUM-HIGH > MEDIUM > LOW > NOISE).

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
        cls, rationale = _classify_qr_axis(axis, values, fact_vector_diff)
        per_axis.append((axis, cls, rationale))

    # Pick the worst (highest-priority) per-axis label.
    per_axis.sort(key=lambda t: _TRIAGE_PRIORITY.get(t[1], 0), reverse=True)
    _top_axis, top_class, top_rationale = per_axis[0]
    return {
        "triage_class": top_class,
        "triage_rationale": top_rationale,
    }


def _classify_qr_axis(
    axis: str, values: Any, full_diff: dict[str, Any]
) -> tuple[str, str]:
    """Per-axis triage logic for the qr family.

    Returns (triage_class, rationale).
    """
    if axis == "decode_outcome":
        return _classify_qr_decode_outcome(values)
    if axis == "detected_text":
        return (
            "MEDIUM-HIGH",
            "detected_text divergence — URL-in-QR phishing surface "
            "(same symbol, different decoded text)",
        )
    if axis == "mode":
        return (
            "MEDIUM",
            "mode divergence — charset-confusion class "
            "(same symbol, different QR data mode)",
        )
    if axis == "encoding_charset":
        return (
            "MEDIUM",
            "encoding_charset divergence — charset-confusion class "
            "(ECI-tagged vs default charset diverges)",
        )
    if axis == "structured_append_index":
        return (
            "MEDIUM",
            "structured_append_index divergence — multi-QR ordering "
            "bug class (structured-append pieces decoded out of order)",
        )
    if axis == "structured_append_total":
        return (
            "MEDIUM",
            "structured_append_total divergence — multi-QR sequence "
            "size disagreement",
        )
    if axis == "fnc1_present":
        return (
            "MEDIUM",
            "fnc1_present divergence — GS1 FNC1 header recognition "
            "differs",
        )
    if axis == "ecc_level":
        return (
            "LOW",
            "ecc_level divergence — error-correction level reporting "
            "differs (cosmetic)",
        )
    if axis == "version":
        return (
            "LOW",
            "version divergence — QR version reporting differs (cosmetic)",
        )
    if axis == "parser_warnings":
        return ("NOISE", "warnings-only divergence")
    # Unknown axis: fall back to NOISE so a future schema addition cannot
    # accidentally promote a benign axis to HIGH.
    return ("NOISE", f"unknown qr-family axis {axis!r}")


def _classify_qr_decode_outcome(values: Any) -> tuple[str, str]:
    """Decode_outcome triage for the qr family.

    The qr fact-vector schema uses the status enum
    {ok, parse_error, decode_error, no_qr_found}. A one-ok-one-parse_error
    pairing is the canonical HIGH signal (one impl decoded cleanly while
    another crashed/rejected the same input — parser crash potential).
    """
    if not isinstance(values, list) or len(values) < 2:
        return ("NOISE", "decode_outcome with <2 observations")

    statuses: list[str] = []
    for v in values:
        if isinstance(v, dict):
            statuses.append(str(v.get("status", "")))
        else:
            statuses.append(str(v))

    has_ok = any(s == "ok" for s in statuses)
    has_parse_error = any(s == "parse_error" for s in statuses)
    has_decode_error = any(s == "decode_error" for s in statuses)
    has_no_qr_found = any(s == "no_qr_found" for s in statuses)

    if has_ok and has_parse_error:
        return (
            "HIGH",
            "decode_outcome divergence (one ok, one parse_error) — parser "
            "crash potential",
        )
    if has_ok and has_decode_error:
        return (
            "MEDIUM-HIGH",
            "decode_outcome divergence (one ok, one decode_error) — parser "
            "acceptance mismatch",
        )
    if has_ok and has_no_qr_found:
        return (
            "MEDIUM",
            "decode_outcome divergence (one ok, one no_qr_found) — "
            "detector-recognition disagreement",
        )
    if has_parse_error and has_decode_error:
        return (
            "MEDIUM",
            "decode_outcome divergence (parse_error vs decode_error) — "
            "parser robustness gap",
        )
    return ("LOW", "decode_outcome divergence without ok pairing")


# ---------------------------------------------------------------------------
# Proto-family triage (T-M2.6)
# ---------------------------------------------------------------------------
#
# Per the T-M2.6 spec, the proto family classifies disagreements as:
#
#   decode_outcome divergence (one ok, one parse_error)        -> HIGH
#       Parser crash potential — one impl decoded cleanly while another
#       crashed/rejected the same input.
#   field_unknown_count divergence                             -> MEDIUM-HIGH
#       Unknown-field-handling bug class (gogo-protobuf vs
#       google-protobuf class).
#   oneof_active_field divergence                              -> MEDIUM-HIGH
#       Oneof-ambiguity class — two decoders pick different fields from
#       the same wire bytes.
#   field_count / decoded_field_summary divergence             -> MEDIUM
#       Decoded-summary disagreement.
#   declared_schema_version divergence                         -> LOW
#       Cosmetic — schema-version declaration differs.
#
# Rules are ADDITIVE — they do not touch URL, image, opengraph,
# deeplink, or qr family classifiers. The proto regression module calls
# `classify_proto_disagreement(fact_vector_diff)` to stamp each emitted
# AG-DIS-PROTO-* record with `triage_class` + rationale.


def classify_proto_disagreement(fact_vector_diff: dict[str, Any]) -> dict[str, str]:
    """Map a proto-family `fact_vector_diff` to triage class + rationale.

    `fact_vector_diff` keys are axis names (e.g. "field_unknown_count",
    "decode_outcome", "oneof_active_field"); values are arrays of
    per-implementation observations. For each axis we evaluate the
    divergence shape and assign a triage label. If the diff touches
    multiple axes the final label is the most severe of the per-axis
    labels (priority HIGH > MEDIUM-HIGH > MEDIUM > LOW > NOISE).

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
        cls, rationale = _classify_proto_axis(axis, values, fact_vector_diff)
        per_axis.append((axis, cls, rationale))

    # Pick the worst (highest-priority) per-axis label.
    per_axis.sort(key=lambda t: _TRIAGE_PRIORITY.get(t[1], 0), reverse=True)
    _top_axis, top_class, top_rationale = per_axis[0]
    return {
        "triage_class": top_class,
        "triage_rationale": top_rationale,
    }


def _classify_proto_axis(
    axis: str, values: Any, full_diff: dict[str, Any]
) -> tuple[str, str]:
    """Per-axis triage logic for the proto family.

    Returns (triage_class, rationale).
    """
    if axis == "decode_outcome":
        return _classify_proto_decode_outcome(values)
    if axis == "field_unknown_count":
        return (
            "MEDIUM-HIGH",
            "field_unknown_count divergence — unknown-field-handling "
            "bug class (gogo-protobuf vs google-protobuf)",
        )
    if axis == "oneof_active_field":
        return (
            "MEDIUM-HIGH",
            "oneof_active_field divergence — oneof-ambiguity class "
            "(same wire bytes resolve to different active fields)",
        )
    if axis == "field_count":
        return (
            "MEDIUM",
            "field_count divergence — decoded-summary disagreement",
        )
    if axis == "decoded_field_summary":
        return (
            "MEDIUM",
            "decoded_field_summary divergence — field values diverge "
            "across decoders",
        )
    if axis == "message_type_name":
        return (
            "MEDIUM",
            "message_type_name divergence — decoders resolved "
            "different message types for the same payload",
        )
    if axis == "format_kind":
        return (
            "MEDIUM",
            "format_kind divergence — decoders disagree on the wire-"
            "format family (protobuf vs flatbuffer vs msgpack)",
        )
    if axis == "declared_schema_version":
        return (
            "LOW",
            "declared_schema_version divergence — cosmetic schema-"
            "version declaration difference",
        )
    if axis == "parser_warnings":
        return ("NOISE", "warnings-only divergence")
    # Unknown axis: fall back to NOISE so a future schema addition cannot
    # accidentally promote a benign axis to HIGH.
    return ("NOISE", f"unknown proto-family axis {axis!r}")


def _classify_proto_decode_outcome(values: Any) -> tuple[str, str]:
    """Decode_outcome triage for the proto family.

    The proto fact-vector schema uses the status enum
    {ok, parse_error, decode_error, schema_mismatch}. A one-ok-one-
    parse_error pairing is the canonical HIGH signal (one impl decoded
    cleanly while another crashed/rejected the same input — parser
    crash potential).
    """
    if not isinstance(values, list) or len(values) < 2:
        return ("NOISE", "decode_outcome with <2 observations")

    statuses: list[str] = []
    for v in values:
        if isinstance(v, dict):
            statuses.append(str(v.get("status", "")))
        else:
            statuses.append(str(v))

    has_ok = any(s == "ok" for s in statuses)
    has_parse_error = any(s == "parse_error" for s in statuses)
    has_decode_error = any(s == "decode_error" for s in statuses)
    has_schema_mismatch = any(s == "schema_mismatch" for s in statuses)

    if has_ok and has_parse_error:
        return (
            "HIGH",
            "decode_outcome divergence (one ok, one parse_error) — parser "
            "crash potential",
        )
    if has_ok and has_decode_error:
        return (
            "MEDIUM-HIGH",
            "decode_outcome divergence (one ok, one decode_error) — parser "
            "acceptance mismatch on syntactically-broken input",
        )
    if has_ok and has_schema_mismatch:
        return (
            "MEDIUM",
            "decode_outcome divergence (one ok, one schema_mismatch) — "
            "schema-recognition disagreement",
        )
    if has_parse_error and has_decode_error:
        return (
            "MEDIUM",
            "decode_outcome divergence (parse_error vs decode_error) — "
            "parser robustness gap on the same input",
        )
    return ("LOW", "decode_outcome divergence without ok pairing")


__all__ = [
    "Disagreement",
    "detect_disagreements",
    "classify_image_disagreement",
    "classify_opengraph_disagreement",
    "classify_deeplink_disagreement",
    "classify_qr_disagreement",
    "classify_proto_disagreement",
]
