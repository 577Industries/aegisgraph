"""embargo_timer default-90d calculation tests.

The timer is pure calculation: reads ledger, returns next-action dates
keyed by finding_id. It does NOT write to the ledger (separation of
concerns; PI sign-off is required to append).
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path

from aegisgraph.disclosure import ledger as disclosure_ledger
from aegisgraph.disclosure.pipeline import embargo_timer


def _vendor_contacted_event(finding_id: str, timestamp: str) -> dict:
    return {
        "entry_id": f"AG-DISC-{timestamp[:4]}{timestamp[5:7]}{timestamp[8:10]}-0001",
        "version": "v1.0",
        "finding_id": finding_id,
        "engine_origin": "polydiff",
        "event_type": "vendor_contacted",
        "timestamp": timestamp,
        "actor": "577_industries_pi",
        "vendor_contact": "security@chromium.org",
        "embargo_days": 90,
        "embargo_until": None,
        "cve_id": None,
        "public_disclosure_url": None,
        "payload_hash_only": "0" * 64,
        "provenance": {
            "generated_by": "test_embargo_timer",
            "generated_at": "2026-05-12T00:00:00Z",
            "source": "tests/disclosure/test_embargo_timer_default_90_days.py",
            "private_by_default": True,
        },
        "safety_flags": [],
    }


def test_default_embargo_is_90_days(tmp_path: Path) -> None:
    """The default per ADR-0014 and vendor_registry.yaml is 90 days."""
    assert embargo_timer.DEFAULT_EMBARGO_DAYS == 90


def test_status_for_freshly_contacted_finding_returns_90_day_next_action(
    tmp_path: Path,
) -> None:
    """A finding that was contacted today gets a next_action_date 90d out."""
    ledger_path = tmp_path / "ledger.jsonl"
    event = _vendor_contacted_event("AG-DIS-IMG-0001", "2026-06-12T10:00:00Z")
    disclosure_ledger.append(event, path=ledger_path)

    statuses = embargo_timer.compute_status(
        ledger_path=ledger_path,
        as_of=date(2026, 6, 12),
    )
    assert len(statuses) == 1
    status = statuses[0]
    assert status["finding_id"] == "AG-DIS-IMG-0001"
    assert status["current_event_type"] == "vendor_contacted"
    assert status["embargo_days"] == 90
    assert status["next_action_date"] == "2026-09-10"


def test_compute_status_empty_ledger_returns_empty_list(tmp_path: Path) -> None:
    """No events in ledger -> no statuses."""
    ledger_path = tmp_path / "ledger.jsonl"
    statuses = embargo_timer.compute_status(
        ledger_path=ledger_path, as_of=date(2026, 6, 12)
    )
    assert statuses == []


def test_compute_status_uses_most_recent_event_per_finding(tmp_path: Path) -> None:
    """If a finding has multiple events, the latest one drives current_event_type."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(
        _vendor_contacted_event("AG-DIS-IMG-0001", "2026-06-12T10:00:00Z"),
        path=ledger_path,
    )
    ack_event = _vendor_contacted_event(
        "AG-DIS-IMG-0001", "2026-06-15T10:00:00Z"
    )
    ack_event["entry_id"] = "AG-DISC-20260615-0002"
    ack_event["event_type"] = "vendor_acknowledged"
    disclosure_ledger.append(ack_event, path=ledger_path)

    statuses = embargo_timer.compute_status(
        ledger_path=ledger_path, as_of=date(2026, 6, 15)
    )
    assert len(statuses) == 1
    assert statuses[0]["current_event_type"] == "vendor_acknowledged"


def test_compute_status_flags_expired_when_past_embargo(tmp_path: Path) -> None:
    """as_of date past embargo_until -> status reports `expired`."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(
        _vendor_contacted_event("AG-DIS-IMG-0001", "2026-06-12T10:00:00Z"),
        path=ledger_path,
    )
    statuses = embargo_timer.compute_status(
        ledger_path=ledger_path, as_of=date(2026, 9, 11)
    )
    assert statuses[0]["expired"] is True
    assert statuses[0]["days_remaining"] < 0


def test_milestone_boundaries_emit_at_7_14_30_60_90(tmp_path: Path) -> None:
    """The cron workflow opens a GH issue at each milestone boundary; the
    timer exposes which milestones a finding has crossed since last tick."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(
        _vendor_contacted_event("AG-DIS-IMG-0001", "2026-06-12T10:00:00Z"),
        path=ledger_path,
    )
    # As of day 30, milestones 7, 14, 30 have passed.
    statuses = embargo_timer.compute_status(
        ledger_path=ledger_path, as_of=date(2026, 7, 12)
    )
    crossed = statuses[0]["milestones_crossed"]
    assert 7 in crossed
    assert 14 in crossed
    assert 30 in crossed
    assert 60 not in crossed
    assert 90 not in crossed
