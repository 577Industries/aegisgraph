"""Enforcement gate: reviewed_embargoed -> disclosed_public.

A finding can only enter `disclosed_public` when:
  1. Its current claim_state is `reviewed_embargoed`.
  2. The disclosure ledger contains at least one of:
       - embargo_expired
       - cve_published
       - disclosure_public
     events for this finding_id.

This module DOES NOT append to the ledger.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegisgraph.claims import transition_allowed
from aegisgraph.disclosure import ledger as disclosure_ledger
from aegisgraph.evidence import finalize_record


REQUIRED_LEDGER_EVENT_TYPES = (
    "embargo_expired",
    "cve_published",
    "disclosure_public",
)
REQUIRED_PRIOR_STATE = "reviewed_embargoed"
TARGET_STATE = "disclosed_public"


class LedgerEventRequiredError(RuntimeError):
    """No qualifying ledger event found for this finding_id."""


class InvalidPriorStateError(RuntimeError):
    """Record's current claim_state is not `reviewed_embargoed`."""


def _ledger_has_event(
    finding_id: str,
    event_types: tuple[str, ...],
    ledger_path: Path | None,
) -> bool:
    for event in disclosure_ledger.iter_events(ledger_path):
        if (
            event.get("finding_id") == finding_id
            and event.get("event_type") in event_types
        ):
            return True
    return False


def enter(
    record: dict[str, Any],
    ledger_path: Path | None = None,
) -> dict[str, Any]:
    """Promote a `reviewed_embargoed` evidence record to `disclosed_public`.

    Raises:
        InvalidPriorStateError: record is not currently `reviewed_embargoed`.
        LedgerEventRequiredError: no qualifying lifecycle event found.

    Returns:
        Finalized record at `disclosed_public`, disclosure_status set to
        `disclosed`, with attached hash_chain block.
    """
    if record.get("claim_state") != REQUIRED_PRIOR_STATE:
        raise InvalidPriorStateError(
            f"record {record.get('id', '<unknown>')!r} is in state "
            f"{record.get('claim_state')!r}; expected "
            f"{REQUIRED_PRIOR_STATE!r} before entering {TARGET_STATE!r}."
        )

    transition = transition_allowed(REQUIRED_PRIOR_STATE, TARGET_STATE)
    if not transition.valid:
        raise InvalidPriorStateError(
            f"transition {REQUIRED_PRIOR_STATE!r} -> {TARGET_STATE!r} "
            f"rejected by claim-state machine: {transition.reason}"
        )

    finding_id = str(record.get("id", ""))
    if not _ledger_has_event(
        finding_id, REQUIRED_LEDGER_EVENT_TYPES, ledger_path
    ):
        raise LedgerEventRequiredError(
            f"cannot enter {TARGET_STATE!r} for finding {finding_id!r}: "
            f"ledger has no event in {REQUIRED_LEDGER_EVENT_TYPES!r}. "
            "Disclosure remains under embargo."
        )

    promoted = dict(record)
    promoted["claim_state"] = TARGET_STATE
    promoted["disclosure_status"] = "disclosed"
    return finalize_record(promoted)
