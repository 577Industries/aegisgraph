"""Rediscovery / triage tests for qr-family anchored corpus.

Per T-M2.5, the qr family ships four anchored cases:

  1. anchor_qr_apple_camera_url_handler — a QR encoding a URL that the
     iOS Camera URL handler extracts differently than ZXing. Detected
     text divergence -> MEDIUM-HIGH (URL-in-QR phishing surface).
  2. anchor_qr_structured_append_misorder — multi-QR structured-append
     decoded out of order between implementations. structured_append
     divergence -> MEDIUM.
  3. anchor_qr_eci_unicode_confusion — ECI-tagged UTF-8 vs default
     Shift-JIS. mode/encoding_charset divergence -> MEDIUM.
  4. anchor_qr_kanji_mode_ambiguity — kanji mode disagreement.
     mode divergence -> MEDIUM.

The witness BYTES are NOT in this repo. They are referenced by SHA-256
only via polydiff/families/qr/regression/corpus.json. This test MOCKS
wrapper outputs deterministically to prove the qr-family disagreement
loop produces the expected triage record on each anchor.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisgraph.io import load_json, repo_root
from aegisgraph.polydiff.core.triage import classify_qr_disagreement


CORPUS_PATH = (
    repo_root()
    / "polydiff"
    / "families"
    / "qr"
    / "regression"
    / "corpus.json"
)


def _load_corpus_case(case_id: str) -> dict[str, Any]:
    corpus = load_json(CORPUS_PATH)
    cases = corpus.get("cases", []) if isinstance(corpus, dict) else corpus
    for case in cases:
        if case.get("case_id") == case_id:
            return case
    raise AssertionError(
        f"case_id {case_id!r} not in corpus.json; have {[c.get('case_id') for c in cases]}"
    )


# ---------------------------------------------------------------------------
# Corpus-pin tests
# ---------------------------------------------------------------------------


def test_corpus_contains_all_four_anchors() -> None:
    corpus = load_json(CORPUS_PATH)
    cases = corpus.get("cases", []) if isinstance(corpus, dict) else corpus
    case_ids = {c.get("case_id") for c in cases}
    required = {
        "anchor_qr_apple_camera_url_handler",
        "anchor_qr_structured_append_misorder",
        "anchor_qr_eci_unicode_confusion",
        "anchor_qr_kanji_mode_ambiguity",
    }
    missing = required - case_ids
    assert not missing, f"qr corpus missing anchored cases: {sorted(missing)}"


def test_corpus_pins_each_case_by_sha256_only() -> None:
    for case_id in (
        "anchor_qr_apple_camera_url_handler",
        "anchor_qr_structured_append_misorder",
        "anchor_qr_eci_unicode_confusion",
        "anchor_qr_kanji_mode_ambiguity",
    ):
        case = _load_corpus_case(case_id)
        assert "witness_sha256" in case
        assert isinstance(case["witness_sha256"], str)
        assert len(case["witness_sha256"]) == 64
        assert all(c in "0123456789abcdef" for c in case["witness_sha256"])
        forbidden = {
            "bytes_b64",
            "payload",
            "raw_bytes",
            "raw_witness",
            "raw_corpus_input",
        }
        assert not (forbidden & set(case.keys())), (
            f"corpus.json must NOT carry payload bytes for {case_id}; "
            f"forbidden keys present: {sorted(forbidden & set(case.keys()))}"
        )


# ---------------------------------------------------------------------------
# Triage-classifier tests
# ---------------------------------------------------------------------------


def test_decode_outcome_one_ok_one_parse_error_is_HIGH() -> None:
    """decode_outcome divergence (one ok, one parse_error) -> HIGH per
    spec (parser crash potential)."""
    fact_vector_diff = {
        "decode_outcome": [
            {"status": "ok", "bytes_out": 64},
            {"status": "parse_error", "bytes_out": 0},
        ],
    }
    triage = classify_qr_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "HIGH", (
        f"decode_outcome divergence (ok + parse_error) must be HIGH; "
        f"got {triage['triage_class']!r}"
    )


def test_detected_text_divergence_is_MEDIUM_HIGH() -> None:
    """detected_text divergence with same input -> MEDIUM-HIGH
    (URL-in-QR phishing surface)."""
    fact_vector_diff = {
        "detected_text": [
            "https://trusted.example/x",
            "https://attacker.example/x",
        ],
    }
    triage = classify_qr_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM-HIGH", (
        f"detected_text divergence must be MEDIUM-HIGH; "
        f"got {triage['triage_class']!r}"
    )
    assert (
        "phish" in triage["triage_rationale"].lower()
        or "url" in triage["triage_rationale"].lower()
        or "text" in triage["triage_rationale"].lower()
    )


def test_mode_divergence_is_MEDIUM() -> None:
    """mode divergence -> MEDIUM (charset-confusion class)."""
    fact_vector_diff = {
        "mode": ["byte", "kanji"],
    }
    triage = classify_qr_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"


def test_encoding_charset_divergence_is_MEDIUM() -> None:
    """encoding_charset divergence -> MEDIUM (charset-confusion class)."""
    fact_vector_diff = {
        "encoding_charset": ["UTF-8", "Shift-JIS"],
    }
    triage = classify_qr_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"
    assert (
        "charset" in triage["triage_rationale"].lower()
        or "encoding" in triage["triage_rationale"].lower()
        or "confusion" in triage["triage_rationale"].lower()
    )


def test_structured_append_index_divergence_is_MEDIUM() -> None:
    """structured_append_index divergence -> MEDIUM (multi-QR ordering bug class)."""
    fact_vector_diff = {
        "structured_append_index": [0, 1],
    }
    triage = classify_qr_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"


def test_structured_append_total_divergence_is_MEDIUM() -> None:
    fact_vector_diff = {
        "structured_append_total": [2, 3],
    }
    triage = classify_qr_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"


def test_ecc_level_divergence_is_LOW() -> None:
    """ecc_level divergence -> LOW (cosmetic)."""
    fact_vector_diff = {
        "ecc_level": ["M", "Q"],
    }
    triage = classify_qr_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "LOW"


def test_version_divergence_is_LOW() -> None:
    fact_vector_diff = {
        "version": [4, 5],
    }
    triage = classify_qr_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "LOW"


def test_empty_diff_is_NOISE() -> None:
    triage = classify_qr_disagreement({})
    assert triage["triage_class"] == "NOISE"


def test_multi_axis_takes_most_severe_label() -> None:
    """When several axes diverge, the classifier picks the worst."""
    fact_vector_diff = {
        "ecc_level": ["M", "Q"],
        "detected_text": [
            "https://a.example",
            "https://b.example",
        ],
    }
    triage = classify_qr_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM-HIGH"


# ---------------------------------------------------------------------------
# End-to-end record emission for the apple-camera-url-handler anchor
# ---------------------------------------------------------------------------


def test_anchored_apple_camera_url_handler_emits_record_with_witness_pin() -> None:
    """Round-trip: feeding the anchored apple-camera-url-handler witness
    through mocked wrappers produces a disagreement record with the
    witness_sha256/witness_size_bytes pin from corpus.json."""
    from aegisgraph.polydiff.families.qr.regression import (
        emit_disagreement_record,
    )

    case = _load_corpus_case("anchor_qr_apple_camera_url_handler")
    base = {
        "input_id": case["case_id"],
        "ecc_level": "M",
        "version": 4,
        "mode": "byte",
        "encoding_charset": "UTF-8",
        "structured_append_index": None,
        "structured_append_total": None,
        "fnc1_present": False,
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 32},
    }
    vectors = [
        {
            **base,
            "parser_profile": "zxing_cli",
            "detected_text": "https://trusted.example/path",
        },
        {
            **base,
            "parser_profile": "ios_detector_stub",
            "detected_text": "https://attacker.example/path",
        },
    ]
    record = emit_disagreement_record(
        case=case, vectors=vectors, previous_hash=None
    )

    assert record["family"] == "qr"
    assert record["witness_sha256"] == case["witness_sha256"]
    assert record["witness_size_bytes"] == case["witness_size_bytes"]
    # detected_text divergence -> MEDIUM-HIGH (URL-in-QR phishing surface).
    assert record["triage_class"] == "MEDIUM-HIGH"
    assert "detected_text" in record["fact_vector_diff"]
    assert record["discovery_engine"] == "polydiff"
    assert "hash_chain" in record
    assert record["hash_chain"]["record_hash"]
    assert record["disagreement_id"].startswith("AG-DIS-QR-")


def test_anchored_record_has_no_blocking_safety_flags() -> None:
    """The emitted AG-DIS-QR-* record must not trip any blocking safety
    patterns."""
    from aegisgraph.polydiff.families.qr.regression import (
        emit_disagreement_record,
    )
    from aegisgraph.safety import blocking_flags, scan_record

    case = _load_corpus_case("anchor_qr_apple_camera_url_handler")
    base = {
        "input_id": case["case_id"],
        "ecc_level": "M",
        "version": 4,
        "mode": "byte",
        "encoding_charset": "UTF-8",
        "structured_append_index": None,
        "structured_append_total": None,
        "fnc1_present": False,
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 32},
    }
    vectors = [
        {
            **base,
            "parser_profile": "zxing_cli",
            "detected_text": "https://trusted.example/x",
        },
        {
            **base,
            "parser_profile": "ios_detector_stub",
            "detected_text": "https://attacker.example/x",
        },
    ]
    record = emit_disagreement_record(case=case, vectors=vectors, previous_hash=None)
    flags = scan_record(record)
    blocks = blocking_flags(flags)
    assert not blocks, (
        f"AG-DIS-QR-* record carries blocking flags: {[f.rule for f in blocks]}"
    )


def test_hash_chain_verifies() -> None:
    """A sample AG-DIS-QR-* record's verify_hash_chain returns []."""
    from aegisgraph.hashchain import verify_hash_chain
    from aegisgraph.polydiff.families.qr.regression import (
        emit_disagreement_record,
    )

    case = _load_corpus_case("anchor_qr_apple_camera_url_handler")
    base = {
        "input_id": case["case_id"],
        "ecc_level": "M",
        "version": 4,
        "mode": "byte",
        "encoding_charset": "UTF-8",
        "structured_append_index": None,
        "structured_append_total": None,
        "fnc1_present": False,
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 32},
    }
    vectors = [
        {
            **base,
            "parser_profile": "zxing_cli",
            "detected_text": "https://a.example",
        },
        {
            **base,
            "parser_profile": "zbar_cli",
            "detected_text": "https://b.example",
        },
    ]
    record = emit_disagreement_record(case=case, vectors=vectors, previous_hash=None)
    errors = verify_hash_chain(record)
    assert errors == [], f"hash-chain verification failed: {errors}"
