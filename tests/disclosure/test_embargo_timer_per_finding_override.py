"""Per-finding embargo override tests.

Some vendors (or counsel-reviewed cases) extend the default 90d. The timer
honors `embargo_days` carried by the most recent ledger event for that
finding, falling back to 90 only when unspecified.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from aegisgraph.disclosure import ledger as disclosure_ledger
from aegisgraph.disclosure.pipeline import embargo_timer


def _event(
    finding_id: str,
    timestamp: str,
    event_type: str = "vendor_contacted",
    embargo_days: int | None = 90,
    entry_id: str | None = None,
) -> dict:
    return {
        "entry_id": entry_id or f"AG-DISC-20260612-{event_type[:4].upper()}",
        "version": "v1.0",
        "finding_id": finding_id,
        "engine_origin": "polydiff",
        "event_type": event_type,
        "timestamp": timestamp,
        "actor": "577_industries_pi",
        "vendor_contact": "security@chromium.org",
        "embargo_days": embargo_days,
        "embargo_until": None,
        "cve_id": None,
        "public_disclosure_url": None,
        "payload_hash_only": "0" * 64,
        "provenance": {
            "generated_by": "test_embargo_timer_override",
            "generated_at": "2026-05-12T00:00:00Z",
            "source": "tests/disclosure/test_embargo_timer_per_finding_override.py",
            "private_by_default": True,
        },
        "safety_flags": [],
    }


def test_per_finding_override_extends_embargo(tmp_path: Path) -> None:
    """A vendor_contacted event with embargo_days=120 produces a 120d
    next_action_date, not 90."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(
        _event(
            "AG-DIS-IMG-0001",
            "2026-06-12T10:00:00Z",
            embargo_days=120,
            entry_id="AG-DISC-20260612-EXTA",
        ),
        path=ledger_path,
    )
    statuses = embargo_timer.compute_status(
        ledger_path=ledger_path, as_of=date(2026, 6, 12)
    )
    # 2026-06-12 + 120d = 2026-10-10
    assert statuses[0]["embargo_days"] == 120
    assert statuses[0]["next_action_date"] == "2026-10-10"


def test_embargo_extended_event_supersedes_initial(tmp_path: Path) -> None:
    """A later embargo_extended event with new embargo_days overrides the
    initial vendor_contacted window."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(
        _event(
            "AG-DIS-IMG-0001",
            "2026-06-12T10:00:00Z",
            embargo_days=90,
            entry_id="AG-DISC-20260612-INIT",
        ),
        path=ledger_path,
    )
    disclosure_ledger.append(
        _event(
            "AG-DIS-IMG-0001",
            "2026-09-01T10:00:00Z",
            event_type="embargo_extended",
            embargo_days=180,
            entry_id="AG-DISC-20260901-EXT2",
        ),
        path=ledger_path,
    )
    statuses = embargo_timer.compute_status(
        ledger_path=ledger_path, as_of=date(2026, 9, 1)
    )
    # 2026-09-01 + 180d = 2027-02-28
    assert statuses[0]["embargo_days"] == 180
    assert statuses[0]["next_action_date"] == "2027-02-28"
    assert statuses[0]["current_event_type"] == "embargo_extended"


def test_missing_embargo_days_falls_back_to_default(tmp_path: Path) -> None:
    """A ledger event with embargo_days=None falls back to 90."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(
        _event(
            "AG-DIS-IMG-0001",
            "2026-06-12T10:00:00Z",
            embargo_days=None,
            entry_id="AG-DISC-20260612-NULL",
        ),
        path=ledger_path,
    )
    statuses = embargo_timer.compute_status(
        ledger_path=ledger_path, as_of=date(2026, 6, 12)
    )
    assert statuses[0]["embargo_days"] == 90
    assert statuses[0]["next_action_date"] == "2026-09-10"


def test_timer_returns_data_only_does_not_append_to_ledger(tmp_path: Path) -> None:
    """The timer is pure calculation — it never writes to the ledger.
    The cron workflow + PI gate is responsible for appending."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(
        _event("AG-DIS-IMG-0001", "2026-06-12T10:00:00Z", entry_id="AG-DISC-20260612-PURE"),
        path=ledger_path,
    )

    before_size = ledger_path.stat().st_size
    embargo_timer.compute_status(
        ledger_path=ledger_path, as_of=date(2026, 7, 12)
    )
    after_size = ledger_path.stat().st_size
    assert before_size == after_size
