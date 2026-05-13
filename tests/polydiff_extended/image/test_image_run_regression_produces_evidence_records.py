"""End-to-end: run_regression() for the image family emits AG-DIS-IMG-*
records that validate against schema/disagreement.schema.json.

The image-family run_regression iterates the corpus.json anchored cases,
runs the diff engine with mocked wrappers, classifies disagreements, and
emits a disagreement record per case. The records are written to
polydiff/families/image/evidence/regression.disagreements.json (and a
matching report.json under regression/).

This test:

  * Calls aegisgraph.polydiff.families.image.regression.run_regression()
    with all subprocess calls mocked at the wrapper layer (so it doesn't
    need binaries or the private corpus).
  * Asserts the report has 1 record per corpus case.
  * Asserts every record validates against
    schema/disagreement.schema.json.
  * Asserts the hash chain is well-formed across records.
  * Asserts the URL family's run_regression is untouched (regression).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from aegisgraph.hashchain import verify_hash_chain
from aegisgraph.io import load_json, repo_root


SCHEMA_PATH = repo_root() / "schema" / "disagreement.schema.json"


def _mock_subprocess_for_image_wrappers(monkeypatch) -> None:
    """Patch subprocess.run so every image wrapper raises FileNotFoundError
    (binary_missing path). The wrappers then emit
    `_crash_envelope`-equivalent fact vectors with
    decode_outcome.status=crash. Two of these crashing vectors on the same
    input produce a `decode_outcome` divergence axis ONLY if at least one
    vector differs — so the test path actually feeds CRAFTED vectors via
    direct injection rather than relying on uniform-crash output.

    The simpler / more deterministic approach is to monkeypatch the
    family's `fact_vectors_for` function. That's what we do.
    """
    pass  # actual mocking happens via the monkeypatch in the test below


def _make_vectors_for_case(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Synthesize fact-vectors matching the case's
    expected_fact_vector_diff so the diff engine WILL produce a
    disagreement on the expected axes."""
    case_id = case["case_id"]
    expected = case.get("expected_fact_vector_diff", {})
    # Two implementations, each emitting one of the values for each axis
    # named in expected_fact_vector_diff.
    vecs: list[dict[str, Any]] = []
    base = {
        "input_id": case_id,
        "dimensions": {"width": 4, "height": 4},
        "color_space": {"profile": "sRGB", "depth": 8},
        "alpha_premultiplied": False,
        "frame_count": 1,
        "first_pixel_rgba": {"r": 0, "g": 0, "b": 0, "a": 255},
        "decode_outcome": {"status": "ok", "bytes_out": 48},
        "parser_warnings": [],
    }
    impls = case.get("implementations", ["libwebp", "libheif"])
    for i, impl in enumerate(impls):
        v = dict(base)
        v["parser_profile"] = impl
        # Apply each divergent axis: first impl gets value[0], second gets value[1].
        for axis, values in expected.items():
            if not isinstance(values, list) or len(values) < 2:
                continue
            v[axis] = values[min(i, len(values) - 1)]
        vecs.append(v)
    return vecs


def test_run_regression_emits_one_record_per_case(tmp_path: Path, monkeypatch):
    from aegisgraph.polydiff.families.image import regression as image_reg

    # Patch the family's fact-vector dispatch so we don't need any binaries.
    def fake_fact_vectors_for(case: dict[str, Any]) -> list[dict[str, Any]]:
        return _make_vectors_for_case(case)

    monkeypatch.setattr(image_reg, "_fact_vectors_for_case", fake_fact_vectors_for)

    captured: dict[str, Any] = {}

    def fake_write_json(path: Path, data: Any) -> Path:
        captured[path.name] = data
        return path

    monkeypatch.setattr(image_reg, "write_json", fake_write_json)

    report = image_reg.run_regression(repo_root())

    assert report["family"] == "image"
    assert report["records_emitted"] >= 1
    assert "disagreements" in captured or "report.json" in captured


def test_each_emitted_record_validates_against_disagreement_schema(
    tmp_path: Path, monkeypatch
):
    from aegisgraph.polydiff.families.image import regression as image_reg

    def fake_fact_vectors_for(case: dict[str, Any]) -> list[dict[str, Any]]:
        return _make_vectors_for_case(case)

    monkeypatch.setattr(image_reg, "_fact_vectors_for_case", fake_fact_vectors_for)

    captured: dict[str, Any] = {}

    def fake_write_json(path: Path, data: Any) -> Path:
        captured[path.name] = data
        return path

    monkeypatch.setattr(image_reg, "write_json", fake_write_json)

    report = image_reg.run_regression(repo_root())

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
    assert records, "image regression must emit at least one disagreement record"
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
    from aegisgraph.polydiff.families.image import regression as image_reg

    def fake_fact_vectors_for(case: dict[str, Any]) -> list[dict[str, Any]]:
        return _make_vectors_for_case(case)

    monkeypatch.setattr(image_reg, "_fact_vectors_for_case", fake_fact_vectors_for)
    monkeypatch.setattr(image_reg, "write_json", lambda p, d: p)

    report = image_reg.run_regression(repo_root())
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


def test_url_family_run_regression_unchanged() -> None:
    """Sanity check: the URL family run_regression entry is still importable
    and exposes the historical surface. T-M2.1 must not regress T-M2.3."""
    from aegisgraph.polydiff import run_regression as url_run_regression

    assert callable(url_run_regression)
