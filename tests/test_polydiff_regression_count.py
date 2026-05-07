"""Regression-count assertions per the engineering plan §11.4."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisgraph.polydiff import run_regression


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def report(monkeypatch) -> dict:
    """Run the regression once and capture the report dict.

    Avoids mutating the working tree by redirecting JSON writes into
    an in-memory dict captured here.
    """
    from aegisgraph import io as iomod
    from aegisgraph import polydiff as polydiffmod

    captured: dict[str, dict] = {}

    def fake_write_json(path: Path, data):
        captured[path.name] = data
        return path

    monkeypatch.setattr(iomod, "write_json", fake_write_json)
    monkeypatch.setattr(polydiffmod, "write_json", fake_write_json)
    return run_regression(REPO_ROOT)


def test_regression_corpus_has_at_least_30_cases(report: dict):
    assert report["inputs_checked"] >= 30, (
        f"engineering plan requires ≥30 regression cases; got {report['inputs_checked']}"
    )


def test_regression_has_at_least_3_historical_cve_cases(report: dict):
    """≥3 cases must carry a historical_cve_or_disclosure_reference."""
    assert report["historical_cve_cases_total"] >= 3


def test_regression_rediscovers_at_least_3_historical_cves(report: dict):
    """The credibility anchor: ≥3 historical CVE/disclosure rediscoveries."""
    assert report["rediscovered_historical_cves"] >= 3, (
        f"got {report['rediscovered_historical_cves']} historical "
        f"rediscoveries; engineering plan requires ≥3"
    )


def test_regression_tier_p1_status_pass(report: dict):
    assert report["tier_p1_status"] == "pass"


def test_regression_uses_real_subprocess_wrappers(report: dict):
    """The runtime parser_profiles must come from PARSER_STATUS, not from
    legacy in-process shims.
    """
    legacy_shims = {"whatwg_like", "guarded_fetcher"}
    runtime_profiles = set(report["parser_profiles"])
    assert not (runtime_profiles & legacy_shims), (
        f"unexpected legacy in-process shim in report: {runtime_profiles & legacy_shims}"
    )
    assert "python_urllib" in runtime_profiles
    assert "whatwg_url_py" in runtime_profiles


def test_index_json_matches_corpus_size(report: dict):
    index_path = REPO_ROOT / "polydiff" / "regression" / "cases" / "INDEX.json"
    assert index_path.exists(), "INDEX.json missing"
    with index_path.open("r", encoding="utf-8") as fh:
        index = json.load(fh)
    assert index["cases_count"] == report["inputs_checked"], (
        f"INDEX.json claims {index['cases_count']} cases; report ran {report['inputs_checked']}"
    )
    assert index["historical_cve_count"] >= 3
