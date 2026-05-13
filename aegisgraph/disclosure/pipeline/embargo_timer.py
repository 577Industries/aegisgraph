"""Embargo timer — pure calculation over the ledger.

Reads `aegisgraph/disclosure/ledger.jsonl`, groups events by finding_id,
and computes the next-action date based on the most recent event's
embargo_days (falling back to DEFAULT_EMBARGO_DAYS=90).

Critically, this module DOES NOT write to the ledger. The cron workflow
consumes its JSON output, and a PI-authorized step appends new events
(embargo_set / embargo_extended / embargo_expired) when appropriate.
This separation enforces the semantic invariant that every ledger
append requires explicit human or counsel review.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from aegisgraph.disclosure import ledger as disclosure_ledger


DEFAULT_EMBARGO_DAYS = 90

# Milestones at which embargo-tick.yml opens a GH issue prompting the
# operator to consider next-stage action (Day-7: file CVE pre-request,
# Day-14: escalate to CERT/CC if no vendor response, Day-30/60/90: status).
MILESTONE_DAYS = (7, 14, 30, 60, 90)


def _parse_event_timestamp(event: dict[str, Any]) -> date:
    raw = str(event.get("timestamp", ""))
    # ISO 8601 with trailing Z -> UTC datetime -> date
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    return datetime.fromisoformat(raw).astimezone(timezone.utc).date()


def _add_days(start: date, days: int) -> date:
    from datetime import timedelta

    return start + timedelta(days=days)


def _group_by_finding(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        finding_id = str(event.get("finding_id", ""))
        if not finding_id:
            continue
        grouped.setdefault(finding_id, []).append(event)
    return grouped


def _latest_event(events: list[dict[str, Any]]) -> dict[str, Any]:
    return sorted(events, key=_parse_event_timestamp)[-1]


def compute_status(
    ledger_path: Path | None = None,
    as_of: date | None = None,
) -> list[dict[str, Any]]:
    """Return per-finding status records.

    Each entry shape:
        {
            "finding_id": str,
            "current_event_type": str,
            "current_event_timestamp": str (ISO date),
            "embargo_days": int,
            "embargo_start_date": str,
            "next_action_date": str,
            "days_remaining": int (negative if expired),
            "expired": bool,
            "milestones_crossed": [int],
        }
    """
    events = disclosure_ledger.read_all(ledger_path)
    if not events:
        return []

    today = as_of or datetime.now(tz=timezone.utc).date()
    grouped = _group_by_finding(events)
    statuses: list[dict[str, Any]] = []

    for finding_id, finding_events in grouped.items():
        latest = _latest_event(finding_events)
        embargo_days = latest.get("embargo_days")
        if not isinstance(embargo_days, int) or embargo_days < 1:
            embargo_days = DEFAULT_EMBARGO_DAYS

        # The embargo clock starts at the earliest vendor_contacted event.
        # Subsequent embargo_extended events reset the window from THEIR
        # own timestamp using the new embargo_days.
        if latest.get("event_type") == "embargo_extended":
            start_date = _parse_event_timestamp(latest)
        else:
            # First vendor_contacted for this finding (or only event).
            contacted = [
                e
                for e in finding_events
                if e.get("event_type") == "vendor_contacted"
            ]
            if contacted:
                start_date = min(_parse_event_timestamp(e) for e in contacted)
            else:
                start_date = _parse_event_timestamp(latest)

        next_action = _add_days(start_date, embargo_days)
        days_elapsed = (today - start_date).days
        days_remaining = (next_action - today).days
        milestones = [m for m in MILESTONE_DAYS if days_elapsed >= m]

        statuses.append(
            {
                "finding_id": finding_id,
                "current_event_type": str(latest.get("event_type", "")),
                "current_event_timestamp": str(latest.get("timestamp", "")),
                "embargo_days": embargo_days,
                "embargo_start_date": start_date.isoformat(),
                "next_action_date": next_action.isoformat(),
                "days_remaining": days_remaining,
                "expired": days_remaining < 0,
                "milestones_crossed": milestones,
            }
        )

    statuses.sort(key=lambda s: s["finding_id"])
    return statuses
