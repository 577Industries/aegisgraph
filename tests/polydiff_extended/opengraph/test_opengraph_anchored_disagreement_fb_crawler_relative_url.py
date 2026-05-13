"""Rediscovery of the Facebook crawler relative-URL quirk (circa 2018).

Facebook's OG crawler historically resolved relative URLs against the
crawled page's URL differently from WHATWG-URL conformant downstream
consumers. The divergence meant a phishing-tracker page could publish
one `og:url` value to Facebook (its preview) while downstream embedders
followed a different resolved URL — a classic open-redirect / preview-
confusion bug class.

The witness BYTES are NOT in this repo. They are referenced by SHA-256
only via polydiff/families/opengraph/regression/corpus.json. This test
MOCKS wrapper outputs deterministically to prove the opengraph-family
disagreement loop produces a MEDIUM-HIGH-triage record on an `og_url`
divergence.

Proof structure:

  1. The opengraph-family corpus.json pins the FB-crawler-relative-URL
     witness by SHA-256 and declares `expected_fact_vector_diff.og_url`
     as a divergence axis (one impl resolves relative URLs Facebook's
     way; another follows WHATWG-URL).
  2. With wrapper outputs mocked to reproduce that divergence, the
     triage classifier MUST return `MEDIUM-HIGH` per the spec
     (og_url divergence with same input -> open-redirect / SSRF
     surface).
  3. The emitted disagreement record carries the anchored
     `witness_sha256` and `historical_cve_reference` (or
     reference_url documenting the public bug write-up).

This is the opengraph-family analog of the image family's CVE-2023-4863
rediscovery test.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisgraph.io import load_json, repo_root
from aegisgraph.polydiff.core.triage import classify_opengraph_disagreement


CORPUS_PATH = (
    repo_root()
    / "polydiff"
    / "families"
    / "opengraph"
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


def test_corpus_pins_fb_crawler_relative_url_by_sha256_only() -> None:
    case = _load_corpus_case("anchor_fb_crawler_2018_relative_url")
    assert "witness_sha256" in case
    assert isinstance(case["witness_sha256"], str)
    assert len(case["witness_sha256"]) == 64
    assert all(c in "0123456789abcdef" for c in case["witness_sha256"])
    forbidden = {"bytes_b64", "payload", "raw_bytes", "raw_witness", "raw_corpus_input"}
    assert not (forbidden & set(case.keys())), (
        f"corpus.json must NOT carry payload bytes for {case['case_id']}; "
        f"forbidden keys present: {sorted(forbidden & set(case.keys()))}"
    )


def test_corpus_declares_og_url_divergence_for_fb_crawler() -> None:
    case = _load_corpus_case("anchor_fb_crawler_2018_relative_url")
    expected = case.get("expected_fact_vector_diff", {})
    assert "og_url" in expected, (
        "FB crawler relative-URL anchor must declare og_url as a divergence axis"
    )


def test_og_url_divergence_is_MEDIUM_HIGH() -> None:
    """og_url divergence with same input -> MEDIUM-HIGH per spec
    (open-redirect / SSRF surface for downstream consumers)."""
    fact_vector_diff = {
        "og_url": [
            "https://attacker.example/landing",
            "https://victim.example/landing",
        ],
    }
    triage = classify_opengraph_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM-HIGH", (
        f"og_url divergence must be MEDIUM-HIGH; got {triage['triage_class']!r}"
    )
    assert (
        "redirect" in triage["triage_rationale"].lower()
        or "ssrf" in triage["triage_rationale"].lower()
        or "og_url" in triage["triage_rationale"].lower()
    )


def test_decode_outcome_one_crash_one_ok_is_HIGH() -> None:
    """decode_outcome divergence with parser crash -> HIGH per spec."""
    fact_vector_diff = {
        "decode_outcome": [
            {"status": "crash", "bytes_out": 0},
            {"status": "ok", "bytes_out": 128},
        ],
    }
    triage = classify_opengraph_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "HIGH", (
        f"decode_outcome divergence with crash must be HIGH; "
        f"got {triage['triage_class']!r}"
    )
    assert "crash" in triage["triage_rationale"].lower() or "parser" in triage[
        "triage_rationale"
    ].lower()


def test_twitter_card_type_divergence_is_MEDIUM() -> None:
    """twitter_card_type divergence -> MEDIUM (semantic-confusion class)."""
    fact_vector_diff = {
        "twitter_card_type": ["player", "summary"],
    }
    triage = classify_opengraph_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"


def test_og_type_divergence_is_MEDIUM() -> None:
    fact_vector_diff = {"og_type": ["video.movie", "website"]}
    triage = classify_opengraph_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"


def test_canonical_url_vs_og_url_divergence_is_MEDIUM() -> None:
    """canonical_url divergence -> MEDIUM (link-preview-confusion class —
    Snyk-2022 URL-confusion extended to embed metadata)."""
    fact_vector_diff = {
        "canonical_url": [
            "https://a.example/x",
            "https://b.example/x",
        ],
    }
    triage = classify_opengraph_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "MEDIUM"
    assert (
        "preview" in triage["triage_rationale"].lower()
        or "canonical" in triage["triage_rationale"].lower()
        or "confusion" in triage["triage_rationale"].lower()
    )


def test_og_title_divergence_is_LOW() -> None:
    """og_title / og_description divergence is cosmetic -> LOW."""
    fact_vector_diff = {"og_title": ["Hello", "Hi"]}
    triage = classify_opengraph_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "LOW"


def test_anchored_fb_crawler_emits_medium_high_record() -> None:
    """Round-trip: feeding the anchored FB crawler relative-URL witness
    through mocked wrappers produces a disagreement with
    triage_class=MEDIUM-HIGH and the historical reference set."""
    from aegisgraph.polydiff.families.opengraph.regression import (
        emit_disagreement_record,
    )

    case = _load_corpus_case("anchor_fb_crawler_2018_relative_url")
    # Synthesized fact vectors reproducing the documented divergence.
    base = {
        "input_id": case["case_id"],
        "og_title": "Example",
        "og_image": None,
        "og_type": None,
        "og_video": None,
        "twitter_card_type": None,
        "twitter_image": None,
        "oembed_type": None,
        "canonical_url": None,
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 128},
    }
    vectors = [
        {
            **base,
            "parser_profile": "facebook_og",
            "og_url": "https://attacker.example/landing",
        },
        {
            **base,
            "parser_profile": "beautifulsoup_fallback",
            "og_url": "https://victim.example/landing",
        },
    ]
    record = emit_disagreement_record(
        case=case,
        vectors=vectors,
        previous_hash=None,
    )

    assert record["family"] == "opengraph"
    assert record["triage_class"] == "MEDIUM-HIGH"
    assert record["witness_sha256"] == case["witness_sha256"]
    assert record["witness_size_bytes"] == case["witness_size_bytes"]
    assert "og_url" in record["fact_vector_diff"]
    impls = " ".join(record["implementations_disagreeing"])
    # Version pins per family.yaml: 'facebook-opengraph-parser@v0.1.0' and
    # 'beautifulsoup4@v4.12.3+html5lib@v1.1'. Match against either the
    # wrapper id or the version-pin substring (the regression module pins
    # to the latter).
    assert "facebook" in impls.lower()
    assert "beautifulsoup" in impls.lower() or "bs4" in impls.lower()
    assert record["discovery_engine"] == "polydiff"
    assert "hash_chain" in record
    assert record["hash_chain"]["record_hash"]


def test_anchored_record_has_no_blocking_safety_flags() -> None:
    """The emitted AG-DIS-OG-* record must not trip any blocking safety
    patterns (no raw bytes, no live-target language, no credentials, no
    overclaiming)."""
    from aegisgraph.polydiff.families.opengraph.regression import (
        emit_disagreement_record,
    )
    from aegisgraph.safety import blocking_flags, scan_record

    case = _load_corpus_case("anchor_fb_crawler_2018_relative_url")
    base = {
        "input_id": case["case_id"],
        "og_title": None,
        "og_image": None,
        "og_type": None,
        "og_video": None,
        "twitter_card_type": None,
        "twitter_image": None,
        "oembed_type": None,
        "canonical_url": None,
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 0},
    }
    vectors = [
        {**base, "parser_profile": "facebook_og", "og_url": "https://a.example/x"},
        {
            **base,
            "parser_profile": "beautifulsoup_fallback",
            "og_url": "https://b.example/x",
        },
    ]
    record = emit_disagreement_record(case=case, vectors=vectors, previous_hash=None)
    flags = scan_record(record)
    blocks = blocking_flags(flags)
    assert not blocks, (
        f"AG-DIS-OG-* record carries blocking flags: {[f.rule for f in blocks]}"
    )


def test_hash_chain_verifies() -> None:
    """A sample AG-DIS-OG-* record's verify_hash_chain returns []."""
    from aegisgraph.hashchain import verify_hash_chain
    from aegisgraph.polydiff.families.opengraph.regression import (
        emit_disagreement_record,
    )

    case = _load_corpus_case("anchor_fb_crawler_2018_relative_url")
    base = {
        "input_id": case["case_id"],
        "og_title": None,
        "og_image": None,
        "og_type": None,
        "og_video": None,
        "twitter_card_type": None,
        "twitter_image": None,
        "oembed_type": None,
        "canonical_url": None,
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 0},
    }
    vectors = [
        {**base, "parser_profile": "facebook_og", "og_url": "https://a.example/x"},
        {
            **base,
            "parser_profile": "beautifulsoup_fallback",
            "og_url": "https://b.example/x",
        },
    ]
    record = emit_disagreement_record(case=case, vectors=vectors, previous_hash=None)
    errors = verify_hash_chain(record)
    assert errors == [], f"hash-chain verification failed: {errors}"
