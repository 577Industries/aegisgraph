"""show_finding resolves evidence_refs to on-disk paths + walks supersedes."""

from __future__ import annotations

import json
from pathlib import Path

from aegisgraph.hashchain import attach_hash_chain
from aegisgraph.workbench.finding_detail import show_finding


def test_show_returns_record_and_engine(fake_repo: Path) -> None:
    envelope = show_finding(fake_repo, "AG-EV-TEST-001")
    assert envelope.get("not_found") is not True
    assert envelope["record"]["id"] == "AG-EV-TEST-001"
    assert envelope["engine"] == "extraction"
    assert envelope["claim_state"] == "observed"


def test_show_returns_not_found_for_unknown_id(fake_repo: Path) -> None:
    envelope = show_finding(fake_repo, "AG-EV-NONEXISTENT-999")
    assert envelope.get("not_found") is True


def test_show_resolves_evidence_ref_command_path(fake_repo: Path) -> None:
    envelope = show_finding(fake_repo, "AG-EV-TEST-001")
    refs = envelope.get("evidence_refs")
    assert isinstance(refs, list) and refs, "expected at least one resolved ref"
    ref = refs[0]
    assert ref["id"] == "REF-TEST-001"
    # The synthetic record's `command` field points at a real on-disk path
    # under the fake repo; the resolver should find it.
    assert "on_disk_paths" in ref
    assert any("extraction/output/test/graph.json" in p for p in ref["on_disk_paths"])


def test_show_walks_supersedes_chain(fake_repo: Path, tmp_path: Path) -> None:
    """A chain of two supersedes records is walked back to root."""
    # Write a second record that supersedes the extraction record.
    promoted = {
        "id": "AG-EV-TEST-001+ANCHORED",
        "version": "v1.0",
        "kind": "workbench_promotion",
        "claim_state": "anchored",
        "supersedes": "AG-EV-TEST-001",
        "promoted_at": "2026-05-13T00:00:00Z",
        "promoted_by": "test@example.invalid",
        "justification": "test chain walk",
        "prior_record_hash": "0" * 64,
        "provenance": {
            "generated_by": "aegisgraph-workbench",
            "generated_at": "2026-05-13T00:00:00Z",
            "source": "workbench_promote",
            "private_by_default": True,
        },
    }
    sealed = attach_hash_chain(promoted, previous_hash=None)
    out = fake_repo / "aegisgraph" / "workbench" / "promotions" / "2026-05-13" / "promoted.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"records": [sealed]}, indent=2, sort_keys=True), encoding="utf-8")

    # Showing the promoted record should walk back to AG-EV-TEST-001.
    envelope = show_finding(fake_repo, "AG-EV-TEST-001+ANCHORED")
    chain = envelope["supersedes_chain"]
    assert len(chain) == 1
    assert chain[0]["record_id"] == "AG-EV-TEST-001"
    assert chain[0]["claim_state"] == "observed"
