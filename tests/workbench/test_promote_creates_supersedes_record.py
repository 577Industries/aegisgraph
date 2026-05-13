"""promote round-trips observed -> anchored -> scored; each step verifies."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aegisgraph.hashchain import verify_hash_chain
from aegisgraph.workbench.cli import cmd_workbench_promote, _build_promoted_record
from aegisgraph.workbench.finding_detail import show_finding


def _promote(root: Path, record_id: str, target_state: str, capsys=None) -> dict:
    """Promote and return the freshly-written record dict.

    Reads the path from the CLI's stdout JSON (deterministic) rather
    than scanning the directory by mtime (which ties on fast FS).
    """
    import io
    import contextlib

    ns = argparse.Namespace(
        root=str(root),
        record_id=record_id,
        to=target_state,
        actor="reviewer@example.invalid",
        justification="round-trip test",
    )
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_workbench_promote(ns)
    assert rc == 0, f"promote returned {rc}"
    line = buf.getvalue()
    info = json.loads(line)
    promoted_path = root / info["path"]
    with promoted_path.open() as fh:
        return json.load(fh)


def test_promote_creates_new_record_with_supersedes(fake_repo: Path) -> None:
    promoted = _promote(fake_repo, "AG-EV-TEST-001", "anchored")
    assert promoted["supersedes"] == "AG-EV-TEST-001"
    assert promoted["claim_state"] == "anchored"
    # Hash chain must verify and link to the prior record_hash.
    assert verify_hash_chain(promoted) == []
    # ADR-0010: new record carries new id (with the +<STATE> suffix).
    assert promoted["id"].endswith("+ANCHORED")
    assert promoted["id"].startswith("AG-EV-TEST-001")


def test_promote_does_not_mutate_prior_record(fake_repo: Path) -> None:
    """Promote must NOT edit the original on-disk file."""
    extract_path = fake_repo / "extraction" / "output" / "test" / "graph.json"
    before = extract_path.read_bytes()
    _promote(fake_repo, "AG-EV-TEST-001", "anchored")
    after = extract_path.read_bytes()
    assert before == after, "promote mutated the prior record's source file"


def test_promote_round_trip_observed_anchored_scored(fake_repo: Path) -> None:
    """observed -> anchored -> scored: each promotion writes a new record."""
    p1 = _promote(fake_repo, "AG-EV-TEST-001", "anchored")
    assert p1["claim_state"] == "anchored"
    # Now promote the new record to scored.
    p2 = _promote(fake_repo, p1["id"], "scored")
    assert p2["claim_state"] == "scored"
    assert p2["supersedes"] == p1["id"]
    # Each promotion verifies its hash chain in isolation.
    assert verify_hash_chain(p1) == []
    assert verify_hash_chain(p2) == []


def test_build_promoted_record_attaches_previous_hash() -> None:
    """The promoted record's hash_chain.previous_hash == prior record_hash."""
    prior_hash = "a" * 64
    new_record = _build_promoted_record(
        prior={"id": "AG-EV-X-001", "claim_state": "observed"},
        prior_record_id="AG-EV-X-001",
        prior_record_hash=prior_hash,
        target_state="anchored",
        actor="me",
        justification="test",
    )
    assert new_record["hash_chain"]["previous_hash"] == prior_hash
    assert verify_hash_chain(new_record) == []
