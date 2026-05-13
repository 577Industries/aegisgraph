"""Pattern extractor canonicalization test.

Given two findings whose underlying structural pattern is identical
(same pattern_type, family, axis, implementations) but differ in
incidental fields (target id, source_finding_id, surface description),
the extractor MUST produce the SAME structural_signature.

This is the central deduplication contract for CrossSMA: a pattern
discovered in Signal Android should match the same pattern discovered
in Element X iff their structural fingerprints agree.

The canonical string is the JSON-canonicalized representation of
{pattern_type, family, axis, implementations_signature}, hashed via
SHA-256.
"""

from __future__ import annotations

import re

from aegisgraph.crosssma.pattern_extractor import (
    PatternFingerprint,
    extract_pattern,
)


def _finding_signal_url_backslash() -> dict[str, object]:
    return {
        "id": "AG-DIS-0001",
        "discovery_engine": "polydiff",
        "pattern_type": "parser_disagreement",
        "family": "url",
        "axis": "backslash_handling",
        "implementations": ["java.net.URI", "whatwg-url"],
        "source_target_id": "signal-android",
        "surface_description": (
            "java.net.URI accepts backslash as host separator while "
            "WHATWG-URL treats it as path"
        ),
    }


def _finding_elementx_url_backslash() -> dict[str, object]:
    # Same structural pattern, observed in a different target with a
    # different surface description and a different evidence record id.
    return {
        "id": "AG-DIS-9999",
        "discovery_engine": "polydiff",
        "pattern_type": "parser_disagreement",
        "family": "url",
        "axis": "backslash_handling",
        # Reorder + alias case — extractor MUST canonicalize the impl set.
        "implementations": ["WHATWG-URL", "java.net.URI"],
        "source_target_id": "element-x-android",
        "surface_description": "Element X URL parser differs in backslash handling",
    }


def _finding_signal_image_frame_count() -> dict[str, object]:
    return {
        "id": "AG-DIS-0042",
        "discovery_engine": "polydiff",
        "pattern_type": "parser_disagreement",
        "family": "image",
        "axis": "frame_count",
        "implementations": ["libwebp", "glide"],
        "source_target_id": "signal-android",
        "surface_description": "frame count divergence",
    }


def test_structurally_equivalent_findings_share_signature() -> None:
    fp_signal = extract_pattern(_finding_signal_url_backslash())
    fp_elementx = extract_pattern(_finding_elementx_url_backslash())
    assert isinstance(fp_signal, PatternFingerprint)
    assert isinstance(fp_elementx, PatternFingerprint)
    assert fp_signal.structural_signature == fp_elementx.structural_signature, (
        "Two structurally-equivalent findings produced different "
        "structural_signatures. Canonicalization is broken: "
        f"signal={fp_signal.structural_signature!r} "
        f"elementx={fp_elementx.structural_signature!r}"
    )


def test_structurally_different_findings_have_distinct_signatures() -> None:
    fp_url = extract_pattern(_finding_signal_url_backslash())
    fp_image = extract_pattern(_finding_signal_image_frame_count())
    assert fp_url.structural_signature != fp_image.structural_signature, (
        "URL pattern and image pattern produced the same signature. "
        "Canonical string must distinguish family+axis."
    )


def test_structural_signature_is_64_char_hex_sha256() -> None:
    fp = extract_pattern(_finding_signal_url_backslash())
    assert re.fullmatch(r"[a-f0-9]{64}", fp.structural_signature), (
        f"structural_signature {fp.structural_signature!r} is not a 64-char hex SHA-256"
    )


def test_pattern_extractor_preserves_pattern_type_enum() -> None:
    fp = extract_pattern(_finding_signal_url_backslash())
    assert fp.pattern_type == "parser_disagreement"


def test_pattern_extractor_round_trip_signature_stable() -> None:
    """Repeated extraction of the same finding yields the same signature."""
    fp_a = extract_pattern(_finding_signal_url_backslash())
    fp_b = extract_pattern(_finding_signal_url_backslash())
    assert fp_a.structural_signature == fp_b.structural_signature


def test_pattern_extractor_canonical_string_present() -> None:
    """The fingerprint carries the canonical-input string used to hash;
    this is what makes the signature auditable / reproducible."""
    fp = extract_pattern(_finding_signal_url_backslash())
    assert fp.canonical_input, "fingerprint must expose canonical_input"
    # Canonical input must mention pattern_type, family, axis.
    for token in ("parser_disagreement", "url", "backslash_handling"):
        assert token in fp.canonical_input, (
            f"canonical_input missing token {token!r}; got {fp.canonical_input!r}"
        )
