"""End-to-end: run_regression() for the opengraph family emits
AG-DIS-OG-* records that validate against schema/disagreement.schema.json.

Mirror of tests/polydiff_extended/image/test_image_run_regression_produces_
evidence_records.py for the opengraph family. Iterates the corpus.json
anchored cases, runs the diff engine with mocked wrappers, classifies
disagreements, and emits a disagreement record per case.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aegisgraph.hashchain import verify_hash_chain
from aegisgraph.io import load_json, repo_root


SCHEMA_PATH = repo_root() / "schema" / "disagreement.schema.json"


def _make_vectors_for_case(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Synthesize fact-vectors matching the case's expected_fact_vector_diff
    so the diff engine will produce the documented disagreement."""
    case_id = case["case_id"]
    expected = case.get("expected_fact_vector_diff", {})
    base = {
        "input_id": case_id,
        "og_title": "Example",
        "og_image": "https://e.example/cover.png",
        "og_type": "article",
        "og_url": "https://e.example/a",
        "og_video": None,
        "twitter_card_type": "summary",
        "twitter_image": "https://e.example/cover.png",
        "oembed_type": None,
        "canonical_url": "https://e.example/a",
        "parser_warnings": [],
        "decode_outcome": {"status": "ok", "bytes_out": 256},
    }
    impls = case.get("implementations", ["facebook_og", "beautifulsoup_fallback"])
    vecs: list[dict[str, Any]] = []
    for i, impl in enumerate(impls):
        v = dict(base)
        v["parser_profile"] = impl
        for axis, values in expected.items():
            if not isinstance(values, list) or len(values) < 2:
                continue
            v[axis] = values[min(i, len(values) - 1)]
        vecs.append(v)
    return vecs


def test_run_regression_emits_one_record_per_case(tmp_path: Path, monkeypatch):
    from aegisgraph.polydiff.families.opengraph import regression as og_reg

    def fake_fact_vectors_for(case: dict[str, Any]) -> list[dict[str, Any]]:
        return _make_vectors_for_case(case)

    monkeypatch.setattr(og_reg, "_fact_vectors_for_case", fake_fact_vectors_for)

    captured: dict[str, Any] = {}

    def fake_write_json(path: Path, data: Any) -> Path:
        captured[path.name] = data
        return path

    monkeypatch.setattr(og_reg, "write_json", fake_write_json)

    report = og_reg.run_regression(repo_root())

    assert report["family"] == "opengraph"
    assert report["records_emitted"] >= 1
    assert "report.json" in captured or "regression.disagreements.json" in captured


def test_each_emitted_record_validates_against_disagreement_schema(
    tmp_path: Path, monkeypatch
):
    from aegisgraph.polydiff.families.opengraph import regression as og_reg

    def fake_fact_vectors_for(case: dict[str, Any]) -> list[dict[str, Any]]:
        return _make_vectors_for_case(case)

    monkeypatch.setattr(og_reg, "_fact_vectors_for_case", fake_fact_vectors_for)
    monkeypatch.setattr(og_reg, "write_json", lambda p, d: p)

    report = og_reg.run_regression(repo_root())

    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
        from referencing import Registry, Resource  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover
        pytest.skip("jsonschema / referencing not available")

    schema = load_json(SCHEMA_PATH)
    hash_chain_schema = load_json(repo_root() / "schema" / "hash-chain.schema.json")
    registry = Registry().with_resources(
        [
            (schema["$id"], Resource.from_contents(schema)),
            ("hash-chain.schema.json", Resource.from_contents(hash_chain_schema)),
            (hash_chain_schema["$id"], Resource.from_contents(hash_chain_schema)),
        ]
    )
    validator = Draft202012Validator(schema, registry=registry)

    records = report["records"]
    assert records, "opengraph regression must emit at least one disagreement record"
    for record in records:
        errors = sorted(validator.iter_errors(record), key=str)
        error_msgs = [
            f"{'/'.join(str(part) for part in e.path)}: {e.message}" for e in errors
        ]
        assert not errors, (
            f"record {record.get('disagreement_id')!r} failed schema validation:\n"
            + "\n".join(error_msgs)
        )


def test_records_form_a_valid_hash_chain(tmp_path: Path, monkeypatch):
    from aegisgraph.polydiff.families.opengraph import regression as og_reg

    def fake_fact_vectors_for(case: dict[str, Any]) -> list[dict[str, Any]]:
        return _make_vectors_for_case(case)

    monkeypatch.setattr(og_reg, "_fact_vectors_for_case", fake_fact_vectors_for)
    monkeypatch.setattr(og_reg, "write_json", lambda p, d: p)

    report = og_reg.run_regression(repo_root())
    records = report["records"]
    assert records

    previous_hash = None
    for record in records:
        errors = verify_hash_chain(record)
        assert errors == [], (
            f"hash-chain verification failed for {record.get('disagreement_id')}: {errors}"
        )
        assert record["hash_chain"]["previous_hash"] == previous_hash, (
            f"chain break at {record.get('disagreement_id')}: "
            f"expected previous_hash={previous_hash}, "
            f"got {record['hash_chain']['previous_hash']}"
        )
        previous_hash = record["hash_chain"]["record_hash"]


def test_url_and_image_families_unchanged() -> None:
    """Sanity check: URL family and image family run_regression entries
    still importable. T-M2.2 must not regress T-M2.1 or T-M2.3."""
    from aegisgraph.polydiff import run_regression as url_run_regression
    from aegisgraph.polydiff.families.image.regression import (
        run_regression as image_run_regression,
    )

    assert callable(url_run_regression)
    assert callable(image_run_regression)


def test_corpus_contains_all_four_anchors() -> None:
    """The opengraph corpus declares the four anchored historical bugs
    enumerated in the T-M2.2 spec:
      * Facebook crawler relative-URL quirk (~2018)
      * Twitter Card player XSS
      * oEmbed provider origin confusion
      * Synthetic meta tag quote-escape divergence
    """
    corpus = load_json(repo_root() / "polydiff" / "families" / "opengraph" / "regression" / "corpus.json")
    cases = corpus.get("cases", []) if isinstance(corpus, dict) else corpus
    case_ids = {c.get("case_id") for c in cases}
    required = {
        "anchor_fb_crawler_2018_relative_url",
        "anchor_twitter_card_player_xss",
        "anchor_oembed_provider_origin_confusion",
        "anchor_synthetic_meta_tag_quote_escape",
    }
    missing = required - case_ids
    assert not missing, f"opengraph corpus missing anchored cases: {sorted(missing)}"
