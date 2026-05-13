"""ADR-0014 hash-chained disclosure-ledger tests.

The ledger uses the same canonicalization (`json-v1-sorted-no-hash-chain`)
as evidence records, so these tests verify the ledger-level chain
contract specifically:

1. Empty ledger reads as empty list.
2. Appending one event produces a verifiable single-line chain with
   `previous_hash: None`.
3. Appending a second event produces a chain with second entry's
   `previous_hash` matching the first's `record_hash`.
4. Mutating any byte of a chain entry breaks verification.
5. Inserting an out-of-order line breaks the chain.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisgraph.disclosure import ledger as disclosure_ledger


def _stub_event(entry_id: str, finding_id: str = "AG-DIS-IMG-0001") -> dict:
    """A minimally-shaped event for chain testing. Does NOT validate
    against the JSON schema (that test lives separately) — this is just
    enough structure for the hash-chain primitives to operate on."""
    return {
        "entry_id": entry_id,
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
        "payload_hash_only": (
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        "provenance": {
            "generated_by": "test_disclosure_ledger",
            "generated_at": "2026-05-12T00:00:00Z",
            "source": "tests/test_disclosure_ledger.py",
            "private_by_default": True,
        },
        "safety_flags": [],
    }


def test_empty_ledger_reads_as_empty_list(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    events = disclosure_ledger.read_all(path)
    assert events == []
    # verify_chain on absent file returns no errors (vacuously valid)
    assert disclosure_ledger.verify_chain(path) == []


def test_single_event_append_produces_verifiable_chain(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    event = _stub_event("AG-DISC-20260612-0001")
    finalized = disclosure_ledger.append(event, path=path)
    assert finalized["hash_chain"]["previous_hash"] is None
    assert finalized["hash_chain"]["canonicalization"] == (
        "json-v1-sorted-no-hash-chain"
    )
    assert len(finalized["hash_chain"]["record_hash"]) == 64
    events = disclosure_ledger.read_all(path)
    assert len(events) == 1
    assert events[0]["entry_id"] == "AG-DISC-20260612-0001"
    assert disclosure_ledger.verify_chain(path) == []


def test_two_event_chain_links_correctly(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    first = disclosure_ledger.append(_stub_event("AG-DISC-20260612-0001"), path=path)
    second_event = _stub_event("AG-DISC-20260619-0002")
    second_event["event_type"] = "vendor_acknowledged"
    second = disclosure_ledger.append(second_event, path=path)
    assert second["hash_chain"]["previous_hash"] == first["hash_chain"]["record_hash"]
    assert disclosure_ledger.verify_chain(path) == []
    assert len(disclosure_ledger.read_all(path)) == 2


def test_mutated_byte_breaks_chain(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(_stub_event("AG-DISC-20260612-0001"), path=path)
    disclosure_ledger.append(_stub_event("AG-DISC-20260619-0002"), path=path)

    # Mutate the first line by re-writing it with a tweaked field.
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    first["vendor_contact"] = "tampered@evil.example"
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    errors = disclosure_ledger.verify_chain(path)
    assert errors, "expected hash-chain verification to flag the tampered first line"
    assert any("record hash mismatch" in e for e in errors)


def test_swapped_order_breaks_chain(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(_stub_event("AG-DISC-20260612-0001"), path=path)
    disclosure_ledger.append(_stub_event("AG-DISC-20260619-0002"), path=path)

    # Swap the two lines.
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    path.write_text(lines[1] + "\n" + lines[0] + "\n", encoding="utf-8")

    errors = disclosure_ledger.verify_chain(path)
    assert errors, "expected hash-chain verification to flag swapped order"


def test_iter_events_streams_in_order(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(_stub_event("AG-DISC-20260612-0001"), path=path)
    disclosure_ledger.append(_stub_event("AG-DISC-20260619-0002"), path=path)
    disclosure_ledger.append(_stub_event("AG-DISC-20260626-0003"), path=path)
    ids = [e["entry_id"] for e in disclosure_ledger.iter_events(path)]
    assert ids == [
        "AG-DISC-20260612-0001",
        "AG-DISC-20260619-0002",
        "AG-DISC-20260626-0003",
    ]


def test_real_ledger_file_is_either_absent_or_empty_in_v04() -> None:
    """Phase II M1 milestone: ledger.jsonl is initialized empty (no
    real disclosure entries yet). If this assertion fails, someone
    appended to the production ledger and we expect a corresponding
    counsel-reviewed `event_type=vendor_contacted` entry to be the
    first line — which only the PI can authorize."""
    real_path = disclosure_ledger.ledger_path()
    if not real_path.exists():
        return  # absent is OK
    content = real_path.read_text(encoding="utf-8").strip()
    assert content == "", (
        f"production ledger {real_path} is NOT empty; if this is "
        "intentional (first real disclosure landed), update this test "
        "to assert the expected first-line shape AND confirm the PI "
        "signed off on the vendor contact."
    )
