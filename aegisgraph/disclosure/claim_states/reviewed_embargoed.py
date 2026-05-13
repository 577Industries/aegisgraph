"""Enforcement gate: reviewed -> reviewed_embargoed.

A finding can only enter `reviewed_embargoed` when:
  1. Its current claim_state is `reviewed`.
  2. The disclosure ledger contains at least one `vendor_contacted`
     event referencing this finding_id.
  3. `aegisgraph.claims.transition_allowed` permits the move.

This module DOES NOT append to the ledger — that's the caller's
responsibility (typically a PI-authorized step). It only validates
preconditions and produces the new finalized evidence record.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegisgraph.claims import transition_allowed
from aegisgraph.disclosure import ledger as disclosure_ledger
from aegisgraph.evidence import finalize_record


REQUIRED_LEDGER_EVENT_TYPES = ("vendor_contacted",)
REQUIRED_PRIOR_STATE = "reviewed"
TARGET_STATE = "reviewed_embargoed"


class LedgerEventRequiredError(RuntimeError):
    """No qualifying ledger event found for this finding_id."""


class InvalidPriorStateError(RuntimeError):
    """Record's current claim_state is not `reviewed`."""


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
    vendor_contact: str,
    ledger_path: Path | None = None,
) -> dict[str, Any]:
    """Promote a `reviewed` evidence record to `reviewed_embargoed`.

    Raises:
        InvalidPriorStateError: record is not currently `reviewed`.
        LedgerEventRequiredError: no vendor_contacted event for this finding.

    Returns:
        The finalized record at state `reviewed_embargoed`, with the
        disclosure_status set to `private_review` and an attached
        hash_chain block. Caller is responsible for persisting it.
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
            f"no {REQUIRED_LEDGER_EVENT_TYPES!r} event in the disclosure "
            "ledger. Append the event first (requires PI sign-off)."
        )

    promoted = dict(record)
    promoted["claim_state"] = TARGET_STATE
    promoted["disclosure_status"] = "private_review"
    promoted["vendor_contact_org_id"] = vendor_contact
    return finalize_record(promoted)
