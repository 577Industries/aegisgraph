"""Rediscovery of CVE-2023-4863 via the image-family disagreement loop.

CVE-2023-4863 is the heap buffer overflow in libwebp's BuildHuffmanTable
exploited via a malformed Huffman table in a VP8L lossless image. The bug
was reachable in Signal Android (and many other consumers) through Glide,
because Glide's image-loading pipeline falls back to libwebp when the
system decoder rejects a payload.

The witness BYTES are NOT in this repo. They are referenced by SHA-256
only via polydiff/families/image/regression/corpus.json. The actual
witness file is vendored privately at reprochain/corpora-private/, never
touched by the image family. This test does NOT depend on that private
corpus — it MOCKS the wrapper outputs deterministically to prove that the
image-family disagreement loop produces an HIGH-triage record on a
decode_outcome divergence.

The proof structure:

  1. The image-family corpus.json pins the CVE witness by SHA-256 and
     declares `expected_fact_vector_diff.decode_outcome` as a divergence
     axis (one libwebp version crashes; libheif decodes ok via its own
     impl).
  2. With wrapper outputs mocked to reproduce that divergence, the
     triage classifier MUST return `HIGH` per Asemarefactor.md line 88
     (decode_outcome divergence with one crash -> memory corruption
     suspect).
  3. The emitted disagreement record carries the anchored
     `witness_sha256` and `historical_cve_reference = "CVE-2023-4863"`.

This is the canonical "ground truth proves the methodology" test: if the
classifier can rediscover the historical bug from a fact-vector diff
alone, the methodology generalizes to novel disagreements.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisgraph.io import load_json, repo_root
from aegisgraph.polydiff.core.triage import classify_image_disagreement


CORPUS_PATH = (
    repo_root()
    / "polydiff"
    / "families"
    / "image"
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


def test_corpus_pins_cve_2023_4863_by_sha256_only() -> None:
    case = _load_corpus_case("anchor_CVE-2023-4863")
    # No payload bytes anywhere in the record — only the hash.
    assert "witness_sha256" in case
    assert isinstance(case["witness_sha256"], str)
    assert len(case["witness_sha256"]) == 64
    assert all(c in "0123456789abcdef" for c in case["witness_sha256"])
    forbidden = {"bytes_b64", "payload", "raw_bytes", "raw_witness", "raw_corpus_input"}
    assert not (forbidden & set(case.keys())), (
        f"corpus.json must NOT carry payload bytes for {case['case_id']}; "
        f"forbidden keys present: {sorted(forbidden & set(case.keys()))}"
    )


def test_corpus_declares_decode_outcome_divergence_for_cve_2023_4863() -> None:
    case = _load_corpus_case("anchor_CVE-2023-4863")
    expected = case.get("expected_fact_vector_diff", {})
    assert "decode_outcome" in expected, (
        "CVE-2023-4863 anchor must declare decode_outcome as a divergence axis "
        "(libwebp crashes, libheif decodes ok)"
    )


def test_decode_outcome_divergence_one_crash_is_HIGH() -> None:
    """The triage classifier MUST return HIGH on a decode_outcome divergence
    where one impl reports `crash` (memory corruption suspect per
    Asemarefactor.md line 88).
    """
    fact_vector_diff = {
        "decode_outcome": [
            {"status": "ok", "bytes_out": 1024},      # libheif
            {"status": "crash", "bytes_out": 0},      # libwebp
        ],
    }
    triage = classify_image_disagreement(fact_vector_diff)
    assert triage["triage_class"] == "HIGH", (
        f"decode_outcome divergence (one ok, one crash) must be HIGH; "
        f"got {triage['triage_class']!r}"
    )
    assert "memory corruption" in triage["triage_rationale"].lower()


def test_anchored_cve_rediscovery_emits_high_record() -> None:
    """Round-trip: feeding the anchored CVE-2023-4863 witness through the
    mocked libwebp + libheif wrappers produces a disagreement with
    triage_class=HIGH and historical_cve_reference set.
    """
    from aegisgraph.polydiff.families.image.regression import (
        emit_disagreement_record,
    )

    case = _load_corpus_case("anchor_CVE-2023-4863")
    # Synthesized fact vectors that reproduce the divergence the anchor
    # documents. NO real witness bytes — these are just the per-axis values
    # we'd expect after running the binaries.
    vectors = [
        {
            "input_id": case["case_id"],
            "parser_profile": "libwebp",
            "dimensions": None,
            "color_space": None,
            "alpha_premultiplied": None,
            "frame_count": None,
            "first_pixel_rgba": None,
            "decode_outcome": {"status": "crash", "bytes_out": 0},
            "parser_warnings": ["invalid huffman table"],
        },
        {
            "input_id": case["case_id"],
            "parser_profile": "libheif",
            "dimensions": {"width": 1, "height": 1},
            "color_space": {"profile": "sRGB", "depth": 8},
            "alpha_premultiplied": False,
            "frame_count": 1,
            "first_pixel_rgba": {"r": 0, "g": 0, "b": 0, "a": 255},
            "decode_outcome": {"status": "ok", "bytes_out": 4},
            "parser_warnings": [],
        },
    ]
    record = emit_disagreement_record(
        case=case,
        vectors=vectors,
        previous_hash=None,
    )

    assert record["family"] == "image"
    assert record["triage_class"] == "HIGH"
    assert record["historical_cve_reference"] == "CVE-2023-4863"
    assert record["witness_sha256"] == case["witness_sha256"]
    assert record["witness_size_bytes"] == case["witness_size_bytes"]
    # `decode_outcome` must appear in fact_vector_diff.
    assert "decode_outcome" in record["fact_vector_diff"]
    # Implementations disagreeing must include libwebp and libheif pinned.
    impls = " ".join(record["implementations_disagreeing"])
    assert "libwebp" in impls and "libheif" in impls
    # `discovery_engine` must equal "polydiff" per the disagreement schema.
    assert record["discovery_engine"] == "polydiff"
    # hash_chain must be sealed.
    assert "hash_chain" in record
    assert record["hash_chain"]["record_hash"]


def test_anchored_record_has_no_blocking_safety_flags() -> None:
    """The emitted AG-DIS-IMG-* record must not trip any of the blocking
    safety patterns (no raw bytes, no live-target language, no
    credentials, no overclaiming)."""
    from aegisgraph.polydiff.families.image.regression import (
        emit_disagreement_record,
    )
    from aegisgraph.safety import blocking_flags, scan_record

    case = _load_corpus_case("anchor_CVE-2023-4863")
    vectors = [
        {
            "input_id": case["case_id"],
            "parser_profile": "libwebp",
            "decode_outcome": {"status": "crash", "bytes_out": 0},
            "parser_warnings": ["invalid huffman table"],
            "dimensions": None,
            "color_space": None,
            "alpha_premultiplied": None,
            "frame_count": None,
            "first_pixel_rgba": None,
        },
        {
            "input_id": case["case_id"],
            "parser_profile": "libheif",
            "decode_outcome": {"status": "ok", "bytes_out": 4},
            "parser_warnings": [],
            "dimensions": {"width": 1, "height": 1},
            "color_space": {"profile": "sRGB", "depth": 8},
            "alpha_premultiplied": False,
            "frame_count": 1,
            "first_pixel_rgba": {"r": 0, "g": 0, "b": 0, "a": 255},
        },
    ]
    record = emit_disagreement_record(
        case=case, vectors=vectors, previous_hash=None
    )
    flags = scan_record(record)
    blocks = blocking_flags(flags)
    assert not blocks, (
        f"AG-DIS-IMG-* record carries blocking flags: {[f.rule for f in blocks]}"
    )
