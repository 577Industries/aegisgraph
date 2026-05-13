"""Claim-state extension: reviewed -> reviewed_embargoed requires a
prior ledger event AND produces a new evidence record at the new state.

The state machine itself (`aegisgraph/claims.py:transition_allowed`)
already allows the transition. This module enforces the higher-level
semantic: you cannot mark a finding `reviewed_embargoed` unless an
authorized vendor_contacted ledger event has been appended for it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisgraph.disclosure import ledger as disclosure_ledger
from aegisgraph.disclosure.claim_states import (
    disclosed_public,
    reviewed_embargoed,
)


def _vendor_contacted_event(finding_id: str) -> dict:
    return {
        "entry_id": "AG-DISC-20260612-0001",
        "version": "v1.0",
        "finding_id": finding_id,
        "engine_origin": "polydiff",
        "event_type": "vendor_contacted",
        "timestamp": "2026-06-12T10:00:00Z",
        "actor": "577_industries_pi",
        "vendor_contact": "security@chromium.org",
        "embargo_days": 90,
        "embargo_until": "2026-09-10",
        "cve_id": None,
        "public_disclosure_url": None,
        "payload_hash_only": "0" * 64,
        "provenance": {
            "generated_by": "test_claim_state",
            "generated_at": "2026-05-12T00:00:00Z",
            "source": "tests/disclosure/test_claim_state_reviewed_to_embargoed_requires_ledger_event.py",
            "private_by_default": True,
        },
        "safety_flags": [],
    }


def _reviewed_record(finding_id: str) -> dict:
    return {
        "id": finding_id,
        "claim_state": "reviewed",
        "limitations": (
            "Reproduced under sanitized harness; behavior is a differential "
            "decode outcome, not an asserted exploitability claim."
        ),
        "recommendation_refs": [],
    }


def test_reviewed_embargoed_requires_prior_ledger_event(tmp_path: Path) -> None:
    """Without a vendor_contacted entry, enter() must fail-closed."""
    ledger_path = tmp_path / "ledger.jsonl"
    record = _reviewed_record("AG-DIS-IMG-0001")
    with pytest.raises(reviewed_embargoed.LedgerEventRequiredError):
        reviewed_embargoed.enter(
            record,
            vendor_contact="security@chromium.org",
            ledger_path=ledger_path,
        )


def test_reviewed_embargoed_succeeds_when_ledger_has_event(
    tmp_path: Path,
) -> None:
    """A prior vendor_contacted event satisfies the precondition; the new
    record carries claim_state=reviewed_embargoed AND the hash chain."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(
        _vendor_contacted_event("AG-DIS-IMG-0001"),
        path=ledger_path,
    )
    record = _reviewed_record("AG-DIS-IMG-0001")
    promoted = reviewed_embargoed.enter(
        record,
        vendor_contact="security@chromium.org",
        ledger_path=ledger_path,
    )
    assert promoted["claim_state"] == "reviewed_embargoed"
    assert promoted["disclosure_status"] == "private_review"
    # finalize_record was called -> hash_chain attached
    assert "hash_chain" in promoted
    assert promoted["hash_chain"]["canonicalization"] == (
        "json-v1-sorted-no-hash-chain"
    )


def test_reviewed_embargoed_rejects_non_reviewed_records(tmp_path: Path) -> None:
    """A claim that hasn't reached `reviewed` cannot jump to embargoed."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(
        _vendor_contacted_event("AG-DIS-IMG-0001"),
        path=ledger_path,
    )
    record = _reviewed_record("AG-DIS-IMG-0001")
    record["claim_state"] = "observed"
    with pytest.raises(reviewed_embargoed.InvalidPriorStateError):
        reviewed_embargoed.enter(
            record,
            vendor_contact="security@chromium.org",
            ledger_path=ledger_path,
        )


def test_disclosed_public_requires_embargo_expired_or_cve_published(
    tmp_path: Path,
) -> None:
    """`disclosed_public` requires either embargo_expired or cve_published
    in the ledger for that finding."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(
        _vendor_contacted_event("AG-DIS-IMG-0001"),
        path=ledger_path,
    )
    record = _reviewed_record("AG-DIS-IMG-0001")
    record["claim_state"] = "reviewed_embargoed"
    with pytest.raises(disclosed_public.LedgerEventRequiredError):
        disclosed_public.enter(record, ledger_path=ledger_path)


def test_disclosed_public_succeeds_after_embargo_expired_event(
    tmp_path: Path,
) -> None:
    """An embargo_expired event in the ledger satisfies disclosed_public."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(
        _vendor_contacted_event("AG-DIS-IMG-0001"),
        path=ledger_path,
    )
    expired = _vendor_contacted_event("AG-DIS-IMG-0001")
    expired["entry_id"] = "AG-DISC-20260910-0002"
    expired["event_type"] = "embargo_expired"
    expired["timestamp"] = "2026-09-10T00:00:00Z"
    expired["actor"] = "embargo_timer"
    disclosure_ledger.append(expired, path=ledger_path)

    record = _reviewed_record("AG-DIS-IMG-0001")
    record["claim_state"] = "reviewed_embargoed"
    promoted = disclosed_public.enter(record, ledger_path=ledger_path)
    assert promoted["claim_state"] == "disclosed_public"
    assert promoted["disclosure_status"] == "disclosed"
    assert "hash_chain" in promoted
