"""Backwards-compat smoke tests for aegisgraph.polydiff.

These tests previously asserted against an in-process synthetic
implementation. Stream/polydiff-core replaces that with a real
subprocess-based dispatcher; the public API surface (Disagreement,
fact_vectors_for, run_regression) is preserved so that callers
continue to work, but the implementation is now backed by real
parsers operating on real regression cases.
"""

from pathlib import Path

import pytest

from aegisgraph.polydiff import detect_disagreements, fact_vectors_for, run_regression


def test_polydiff_detects_parser_disagreement_on_backslash():
    """The IE-legacy backslash case should produce a disagreement.

    With python_urllib + whatwg_url_py both available in the
    environment, urllib parses 'evil.example' as host while
    whatwg-url converts the backslash to a slash and parses
    'example.com' as host.
    """
    vectors = fact_vectors_for("T", r"https://example.com\@evil.example/")
    assert vectors, "expected at least one parser wrapper to dispatch"
    disagreements = detect_disagreements(vectors)
    assert disagreements, "expected at least one disagreement on backslash case"
    axes = {d.axis for d in disagreements}
    # We expect host_lowercased OR host (both forms count as origin
    # confusion). Don't pin to a specific axis name in case the
    # detector list grows.
    assert axes & {"host", "host_lowercased", "backslash_treated_as_slash"}, axes


def test_polydiff_regression_produces_tier_p1_pass(tmp_path: Path, monkeypatch):
    """run_regression must reach tier_p1_status='pass' on the corpus.

    The test runs against the real corpus in the repo (so the run
    exercises the actual parser wrappers + classifier + chained
    record hashing), and merely redirects the JSON outputs into
    `tmp_path` so the test does not mutate the working tree.
    """
    from aegisgraph import io as iomod
    from aegisgraph import polydiff as polydiffmod

    real_root = Path(__file__).resolve().parents[1]
    captured: dict[str, dict] = {}

    def fake_write_json(path: Path, data):
        captured[path.name] = data
        return path

    monkeypatch.setattr(iomod, "write_json", fake_write_json)
    monkeypatch.setattr(polydiffmod, "write_json", fake_write_json)

    report = run_regression(real_root)

    assert report["tier_p1_status"] == "pass", (
        f"expected pass; got {report['tier_p1_status']}; "
        f"rediscovered_historical_cves={report['rediscovered_historical_cves']}"
    )
    assert report["rediscovered_historical_cves"] >= 3
    assert report["inputs_checked"] >= 30
    assert "report.json" in captured
    assert "regression.evidence.json" in captured


def test_polydiff_disagreement_dataclass_round_trip():
    """Disagreement dataclass to_dict shape stays stable for callers."""
    vectors = fact_vectors_for("T", "http://0177.0.0.1/")
    disagreements = detect_disagreements(vectors)
    assert disagreements
    d = disagreements[0]
    payload = d.to_dict()
    assert set(payload.keys()) == {"input_id", "axis", "parser_values", "security_tags"}
    assert payload["input_id"] == "T"
