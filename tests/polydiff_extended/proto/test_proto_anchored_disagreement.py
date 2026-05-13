"""Rediscovery / triage tests for proto-family anchored corpus.

Per T-M2.6, the proto family ships four anchored cases:

  1. anchor_proto_unknown_field_handling — gogo-protobuf vs
     google-protobuf disagree on handling of unknown fields.
     field_unknown_count divergence -> MEDIUM-HIGH (unknown-field bug class).
  2. anchor_proto_oneof_ambiguity — same wire bytes resolve to
     different active oneof field. oneof_active_field divergence ->
     MEDIUM-HIGH (oneof-ambiguity class).
  3. anchor_flatbuffer_offset_overflow — flatc vs google-protobuf-as-flat
     differ on out-of-range offset handling. decode_outcome divergence
     (ok vs parse_error) -> HIGH.
  4. anchor_msgpack_ext_type_collision — same payload bytes resolve to
     different ext types. decoded_field_summary divergence -> MEDIUM.

The witness BYTES are NOT in this repo. They are referenced by SHA-256
only via polydiff/families/proto/regression/corpus.json. This test
MOCKS wrapper outputs deterministically to prove the proto-family
disagreement loop produces the expected triage record on each anchor.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisgraph.io import load_json, repo_root
from aegisgraph.polydiff.core.triage import classify_proto_disagreement


CORPUS_PATH = (
    repo_root()
    / "polydiff"
    / "families"
    / "proto"
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
        "anchor_proto_unknown_field_handling",
        "anchor_proto_oneof_ambiguity",
        "anchor_flatbuffer_offset_overflow",
        "anchor_msgpack_ext_type_collision",
    }
    missing = required - case_ids
    assert not missing, f"proto corpus missing anchored cases: {sorted(missing)}"


def test_corpus_pins_each_case_by_sha256_only() -> None:
    for case_id in (
        "anchor_proto_unknown_field_handling",
        "anchor_proto_oneof_ambiguity",
        "anchor_flatbuffer_offset_overflow",
        "anchor_msgpack_ext_type_collision",
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
    triage = classify_proto_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "HIGH", (
        f"decode_outcome divergence (ok + parse_error) must be HIGH; "
        f"got {triage['triage_class']!r}"
    )


def test_field_unknown_count_divergence_is_MEDIUM_HIGH() -> None:
    """field_unknown_count divergence -> MEDIUM-HIGH per spec
    (unknown-field-handling bug class)."""
    fact_vector_diff = {
        "field_unknown_count": [0, 2],
    }
    triage = classify_proto_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM-HIGH", (
        f"field_unknown_count divergence must be MEDIUM-HIGH; "
        f"got {triage['triage_class']!r}"
    )
    assert (
        "unknown" in triage["triage_rationale"].lower()
        or "field" in triage["triage_rationale"].lower()
    )


def test_oneof_active_field_divergence_is_MEDIUM_HIGH() -> None:
    """oneof_active_field divergence -> MEDIUM-HIGH per spec
    (oneof-ambiguity class)."""
    fact_vector_diff = {
        "oneof_active_field": ["payload_a", "payload_b"],
    }
    triage = classify_proto_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM-HIGH"
    assert (
        "oneof" in triage["triage_rationale"].lower()
        or "ambig" in triage["triage_rationale"].lower()
    )


def test_field_count_divergence_is_MEDIUM() -> None:
    """field_count divergence -> MEDIUM (decoded-summary disagreement)."""
    fact_vector_diff = {
        "field_count": [3, 4],
    }
    triage = classify_proto_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"


def test_decoded_field_summary_divergence_is_MEDIUM() -> None:
    fact_vector_diff = {
        "decoded_field_summary": [{"id": 1}, {"id": 2}],
    }
    triage = classify_proto_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"


def test_declared_schema_version_divergence_is_LOW() -> None:
    """declared_schema_version divergence -> LOW (cosmetic)."""
    fact_vector_diff = {
        "declared_schema_version": ["v2", "v3"],
    }
    triage = classify_proto_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "LOW"


def test_empty_diff_is_NOISE() -> None:
    triage = classify_proto_disagreement({})
    assert triage["triage_class"] == "NOISE"


def test_multi_axis_takes_most_severe_label() -> None:
    """When several axes diverge, the classifier picks the worst."""
    fact_vector_diff = {
        "declared_schema_version": ["v2", "v3"],
        "field_unknown_count": [0, 2],
    }
    triage = classify_proto_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM-HIGH"


# ---------------------------------------------------------------------------
# End-to-end record emission for the unknown_field_handling anchor
# ---------------------------------------------------------------------------


def test_anchored_unknown_field_handling_emits_record_with_witness_pin() -> None:
    """Round-trip: feeding the anchored unknown-field-handling witness
    through mocked wrappers produces a disagreement record with the
    witness_sha256/witness_size_bytes pin from corpus.json."""
    from aegisgraph.polydiff.families.proto.regression import (
        emit_disagreement_record,
    )

    case = _load_corpus_case("anchor_proto_unknown_field_handling")
    base = {
        "input_id": case["case_id"],
        "format_kind": "protobuf",
        "declared_schema_version": "v3",
        "message_type_name": "com.example.Message",
        "field_count": 5,
        "oneof_active_field": None,
        "decoded_field_summary": {"id": 1},
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 64},
    }
    vectors = [
        {
            **base,
            "parser_profile": "protoc_python",
            "field_unknown_count": 0,
        },
        {
            **base,
            "parser_profile": "protoc_gogofaster_stub",
            "field_unknown_count": 2,
        },
    ]
    record = emit_disagreement_record(
        case=case, vectors=vectors, previous_hash=None
    )

    assert record["family"] == "proto"
    assert record["witness_sha256"] == case["witness_sha256"]
    assert record["witness_size_bytes"] == case["witness_size_bytes"]
    # field_unknown_count divergence -> MEDIUM-HIGH.
    assert record["triage_class"] == "MEDIUM-HIGH"
    assert "field_unknown_count" in record["fact_vector_diff"]
    assert record["discovery_engine"] == "polydiff"
    assert "hash_chain" in record
    assert record["hash_chain"]["record_hash"]
    assert record["disagreement_id"].startswith("AG-DIS-PROTO-")


def test_anchored_record_has_no_blocking_safety_flags() -> None:
    """The emitted AG-DIS-PROTO-* record must not trip any blocking safety
    patterns."""
    from aegisgraph.polydiff.families.proto.regression import (
        emit_disagreement_record,
    )
    from aegisgraph.safety import blocking_flags, scan_record

    case = _load_corpus_case("anchor_proto_unknown_field_handling")
    base = {
        "input_id": case["case_id"],
        "format_kind": "protobuf",
        "declared_schema_version": "v3",
        "message_type_name": "com.example.Message",
        "field_count": 5,
        "oneof_active_field": None,
        "decoded_field_summary": {"id": 1},
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 0},
    }
    vectors = [
        {
            **base,
            "parser_profile": "protoc_python",
            "field_unknown_count": 0,
        },
        {
            **base,
            "parser_profile": "protoc_gogofaster_stub",
            "field_unknown_count": 2,
        },
    ]
    record = emit_disagreement_record(case=case, vectors=vectors, previous_hash=None)
    flags = scan_record(record)
    blocks = blocking_flags(flags)
    assert not blocks, (
        f"AG-DIS-PROTO-* record carries blocking flags: {[f.rule for f in blocks]}"
    )


def test_hash_chain_verifies() -> None:
    """A sample AG-DIS-PROTO-* record's verify_hash_chain returns []."""
    from aegisgraph.hashchain import verify_hash_chain
    from aegisgraph.polydiff.families.proto.regression import (
        emit_disagreement_record,
    )

    case = _load_corpus_case("anchor_proto_unknown_field_handling")
    base = {
        "input_id": case["case_id"],
        "format_kind": "protobuf",
        "declared_schema_version": "v3",
        "message_type_name": "com.example.Message",
        "field_count": 5,
        "oneof_active_field": None,
        "decoded_field_summary": {"id": 1},
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 0},
    }
    vectors = [
        {**base, "parser_profile": "protoc_python", "field_unknown_count": 0},
        {**base, "parser_profile": "msgpack_python", "field_unknown_count": 2},
    ]
    record = emit_disagreement_record(case=case, vectors=vectors, previous_hash=None)
    errors = verify_hash_chain(record)
    assert errors == [], f"hash-chain verification failed: {errors}"
