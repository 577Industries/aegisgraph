"""Registry returns an engine-filtered FindingRow list."""

from __future__ import annotations

from pathlib import Path

from aegisgraph.workbench.filters import FindingFilters
from aegisgraph.workbench.finding_list import list_findings
from aegisgraph.workbench.registry import scan


def test_scan_picks_up_one_record_per_engine(fake_repo: Path) -> None:
    rows = scan(fake_repo)
    engines = {row.engine for row in rows}
    assert "extraction" in engines
    assert "polydiff" in engines
    assert "harnessgen" in engines
    assert "invariantcheck" in engines
    assert "crosssma" in engines
    # The synthetic fixture writes exactly one record per engine.
    assert len(rows) == 5


def test_list_filter_engine_polydiff_returns_one_row(fake_repo: Path) -> None:
    rows = list_findings(fake_repo, FindingFilters(engine="polydiff"))
    assert len(rows) == 1
    assert rows[0]["engine"] == "polydiff"
    assert rows[0]["record_id"] == "AG-DIS-TEST-URL-001"


def test_list_filter_engine_invariantcheck_returns_one_row(fake_repo: Path) -> None:
    rows = list_findings(fake_repo, FindingFilters(engine="invariantcheck"))
    assert [r["record_id"] for r in rows] == ["AG-IV-TEST-001"]


def test_list_no_filter_returns_all_rows_sorted_by_score(fake_repo: Path) -> None:
    rows = list_findings(fake_repo, FindingFilters())
    # Score-descending: the extraction record carries total=5.0, others 0.
    assert rows[0]["record_id"] == "AG-EV-TEST-001"
    # Stable secondary sort on record_id ascending for the 0-score tail.
    tail_ids = [r["record_id"] for r in rows[1:]]
    assert tail_ids == sorted(tail_ids)


def test_list_filter_target_substring(fake_repo: Path) -> None:
    rows = list_findings(fake_repo, FindingFilters(target="signal"))
    # Both extraction (Signal Android) and invariantcheck (target_id=signal_android)
    # match.
    ids = {r["record_id"] for r in rows}
    assert "AG-EV-TEST-001" in ids
    assert "AG-IV-TEST-001" in ids
