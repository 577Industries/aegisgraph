"""Rediscovery / triage tests for deeplink-family anchored corpus.

Per T-M2.4, the deeplink family ships four anchored cases:

  1. anchor_android_intent_implicit_export — intent:// URI that, when
     parsed by Android's Intent.parseUri, produces an Intent with an
     action matching a non-declared filter (silent-export risk).
     Expected triage class: MEDIUM-HIGH (intent_action divergence,
     Android intent-confusion bug class).
  2. anchor_ios_universal_link_origin_confusion — HTTPS URL that
     NSURLComponents parses one way and the SMA's link-handler parses
     differently (origin-confusion). Expected: MEDIUM (host/path
     divergence, parser inconsistency / redirect surface).
  3. anchor_deeplink_open_redirect — signal:// URI with an embedded
     HTTP URL in a parameter; if the SMA fetches the parameter
     without policy check, open redirect. Maps to a historical
     deeplink bug class. Expected: MEDIUM (host/path divergence or
     query_params divergence).
  4. anchor_custom_scheme_traversal — custom scheme (sgnl://chat/../..//
     system/) where the path component admits traversal. Expected:
     MEDIUM (path divergence).

The witness BYTES are NOT in this repo. They are referenced by SHA-256
only via polydiff/families/deeplink/regression/corpus.json. This test
MOCKS wrapper outputs deterministically to prove the deeplink-family
disagreement loop produces the expected triage record on each anchor.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisgraph.io import load_json, repo_root
from aegisgraph.polydiff.core.triage import classify_deeplink_disagreement


CORPUS_PATH = (
    repo_root()
    / "polydiff"
    / "families"
    / "deeplink"
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
        "anchor_android_intent_implicit_export",
        "anchor_ios_universal_link_origin_confusion",
        "anchor_deeplink_open_redirect",
        "anchor_custom_scheme_traversal",
    }
    missing = required - case_ids
    assert not missing, f"deeplink corpus missing anchored cases: {sorted(missing)}"


def test_corpus_pins_each_case_by_sha256_only() -> None:
    for case_id in (
        "anchor_android_intent_implicit_export",
        "anchor_ios_universal_link_origin_confusion",
        "anchor_deeplink_open_redirect",
        "anchor_custom_scheme_traversal",
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
    """decode_outcome divergence (one ok, one parse_error) -> HIGH per spec
    (parser crash potential)."""
    fact_vector_diff = {
        "decode_outcome": [
            {"status": "ok", "bytes_out": 128},
            {"status": "parse_error", "bytes_out": 0},
        ],
    }
    triage = classify_deeplink_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "HIGH", (
        f"decode_outcome divergence (ok + parse_error) must be HIGH; "
        f"got {triage['triage_class']!r}"
    )
    assert (
        "parse" in triage["triage_rationale"].lower()
        or "crash" in triage["triage_rationale"].lower()
        or "decode" in triage["triage_rationale"].lower()
    )


def test_intent_action_divergence_is_MEDIUM_HIGH() -> None:
    """intent_action divergence -> MEDIUM-HIGH per spec
    (Android intent-confusion bug class)."""
    fact_vector_diff = {
        "intent_action": [
            "android.intent.action.VIEW",
            "android.intent.action.SEND",
        ],
    }
    triage = classify_deeplink_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM-HIGH", (
        f"intent_action divergence must be MEDIUM-HIGH; "
        f"got {triage['triage_class']!r}"
    )
    assert (
        "intent" in triage["triage_rationale"].lower()
        or "android" in triage["triage_rationale"].lower()
        or "confusion" in triage["triage_rationale"].lower()
    )


def test_host_divergence_is_MEDIUM() -> None:
    """host divergence -> MEDIUM (parser inconsistency / redirect surface)."""
    fact_vector_diff = {
        "host": ["attacker.example", "victim.example"],
    }
    triage = classify_deeplink_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"
    assert (
        "host" in triage["triage_rationale"].lower()
        or "redirect" in triage["triage_rationale"].lower()
        or "parser" in triage["triage_rationale"].lower()
    )


def test_path_divergence_is_MEDIUM() -> None:
    fact_vector_diff = {
        "path": ["/chat/abc", "/admin"],
    }
    triage = classify_deeplink_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"


def test_declared_permissions_divergence_is_MEDIUM() -> None:
    """declared_permissions divergence -> MEDIUM (Android implicit-export)."""
    fact_vector_diff = {
        "declared_permissions": [
            ["android.permission.CAMERA"],
            [],
        ],
    }
    triage = classify_deeplink_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"
    assert (
        "permission" in triage["triage_rationale"].lower()
        or "implicit" in triage["triage_rationale"].lower()
        or "export" in triage["triage_rationale"].lower()
    )


def test_fragment_action_divergence_is_MEDIUM() -> None:
    fact_vector_diff = {
        "fragment_action": ["#openLink", "#viewProfile"],
    }
    triage = classify_deeplink_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"


def test_query_params_divergence_is_LOW() -> None:
    """query_params divergence -> LOW (often spec-tolerant)."""
    fact_vector_diff = {
        "query_params": [{"a": "1"}, {"a": "1", "b": "2"}],
    }
    triage = classify_deeplink_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "LOW"


def test_empty_diff_is_NOISE() -> None:
    triage = classify_deeplink_disagreement({})
    assert triage["triage_class"] == "NOISE"


def test_multi_axis_takes_most_severe_label() -> None:
    """When several axes diverge, the classifier picks the worst."""
    fact_vector_diff = {
        "query_params": [{"a": "1"}, {"b": "2"}],
        "intent_action": ["android.intent.action.VIEW", "android.intent.action.SEND"],
    }
    triage = classify_deeplink_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM-HIGH"


# ---------------------------------------------------------------------------
# End-to-end record emission for the open_redirect anchor
# ---------------------------------------------------------------------------


def test_anchored_open_redirect_emits_record_with_witness_pin() -> None:
    """Round-trip: feeding the anchored open-redirect witness through
    mocked wrappers produces a disagreement record with the
    witness_sha256/witness_size_bytes pin from corpus.json."""
    from aegisgraph.polydiff.families.deeplink.regression import (
        emit_disagreement_record,
    )

    case = _load_corpus_case("anchor_deeplink_open_redirect")
    base = {
        "input_id": case["case_id"],
        "scheme": "signal",
        "fragment_action": None,
        "declared_permissions": [],
        "intent_action": None,
        "intent_category": None,
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 64},
    }
    vectors = [
        {
            **base,
            "parser_profile": "custom_scheme_parser",
            "host": "victim.example",
            "path": "/redirect",
            "query_params": {"to": "https://attacker.example/landing"},
        },
        {
            **base,
            "parser_profile": "web_url_fallback",
            "host": "attacker.example",
            "path": "/landing",
            "query_params": {},
        },
    ]
    record = emit_disagreement_record(
        case=case, vectors=vectors, previous_hash=None
    )

    assert record["family"] == "deeplink"
    assert record["witness_sha256"] == case["witness_sha256"]
    assert record["witness_size_bytes"] == case["witness_size_bytes"]
    # The open_redirect anchor produces host + path divergence -> MEDIUM
    # (parser inconsistency / redirect surface).
    assert record["triage_class"] == "MEDIUM"
    assert "host" in record["fact_vector_diff"] or "path" in record["fact_vector_diff"]
    impls = " ".join(record["implementations_disagreeing"])
    assert "custom" in impls.lower() or "scheme" in impls.lower()
    assert "url" in impls.lower() or "whatwg" in impls.lower() or "web" in impls.lower()
    assert record["discovery_engine"] == "polydiff"
    assert "hash_chain" in record
    assert record["hash_chain"]["record_hash"]
    assert record["disagreement_id"].startswith("AG-DIS-DL-")


def test_anchored_record_has_no_blocking_safety_flags() -> None:
    """The emitted AG-DIS-DL-* record must not trip any blocking safety
    patterns."""
    from aegisgraph.polydiff.families.deeplink.regression import (
        emit_disagreement_record,
    )
    from aegisgraph.safety import blocking_flags, scan_record

    case = _load_corpus_case("anchor_deeplink_open_redirect")
    base = {
        "input_id": case["case_id"],
        "scheme": "signal",
        "fragment_action": None,
        "declared_permissions": [],
        "intent_action": None,
        "intent_category": None,
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 0},
    }
    vectors = [
        {
            **base,
            "parser_profile": "custom_scheme_parser",
            "host": "victim.example",
            "path": "/x",
            "query_params": {"to": "https://attacker.example/y"},
        },
        {
            **base,
            "parser_profile": "web_url_fallback",
            "host": "attacker.example",
            "path": "/y",
            "query_params": {},
        },
    ]
    record = emit_disagreement_record(case=case, vectors=vectors, previous_hash=None)
    flags = scan_record(record)
    blocks = blocking_flags(flags)
    assert not blocks, (
        f"AG-DIS-DL-* record carries blocking flags: {[f.rule for f in blocks]}"
    )


def test_hash_chain_verifies() -> None:
    """A sample AG-DIS-DL-* record's verify_hash_chain returns []."""
    from aegisgraph.hashchain import verify_hash_chain
    from aegisgraph.polydiff.families.deeplink.regression import (
        emit_disagreement_record,
    )

    case = _load_corpus_case("anchor_deeplink_open_redirect")
    base = {
        "input_id": case["case_id"],
        "scheme": "signal",
        "fragment_action": None,
        "declared_permissions": [],
        "intent_action": None,
        "intent_category": None,
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 0},
    }
    vectors = [
        {
            **base,
            "parser_profile": "custom_scheme_parser",
            "host": "a.example",
            "path": "/x",
            "query_params": {},
        },
        {
            **base,
            "parser_profile": "web_url_fallback",
            "host": "b.example",
            "path": "/x",
            "query_params": {},
        },
    ]
    record = emit_disagreement_record(case=case, vectors=vectors, previous_hash=None)
    errors = verify_hash_chain(record)
    assert errors == [], f"hash-chain verification failed: {errors}"
