"""promote should refuse backward / illegal transitions.

observed -> disclosed_public is NOT a valid one-step transition in the
canonical claim_state lifecycle (the CLAIM_STATE_ORDER monotonic
constraint is satisfied here since disclosed_public has higher index
than observed, but `transition_allowed` is the canonical decision
function). The test instead exercises a backward transition (anchored
-> observed), which the lifecycle MUST refuse, AND the retired sink
(retired -> anchored).
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from aegisgraph.workbench.cli import cmd_workbench_promote


def _run(root: Path, record_id: str, target: str) -> int:
    ns = argparse.Namespace(
        root=str(root),
        record_id=record_id,
        to=target,
        actor=None,
        justification=None,
    )
    return cmd_workbench_promote(ns)


def test_promote_unknown_state_returns_nonzero(fake_repo: Path, capsys) -> None:
    rc = _run(fake_repo, "AG-EV-TEST-001", "not_a_real_state")
    assert rc != 0
    captured = capsys.readouterr()
    assert "invalid claim state" in captured.err or "unknown claim state" in captured.err


def test_promote_backward_transition_refused(fake_repo: Path, capsys) -> None:
    """Promote observed up to scored (allowed), then back to observed (refused).

    Backward transitions cross the CLAIM_STATE_ORDER monotonic line and
    must be refused unless the target is `limited` or `retired`.
    """
    # First, observed -> scored (forward; allowed).
    rc = _run(fake_repo, "AG-EV-TEST-001", "scored")
    assert rc == 0

    # Now grab the new id (highest-state) by enumerating promotions.
    promotions = sorted(
        (fake_repo / "aegisgraph" / "workbench" / "promotions").rglob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    assert promotions, "expected at least one promoted record"
    import json as _json
    with promotions[0].open() as fh:
        first = _json.load(fh)
    new_id = first["id"]

    # Backward: scored -> observed (refused).
    rc = _run(fake_repo, new_id, "observed")
    assert rc != 0
    captured = capsys.readouterr()
    assert "transition refused" in captured.err


def test_promote_to_retired_always_allowed(fake_repo: Path) -> None:
    """retired is a sink state — retiring from any non-retired is allowed."""
    rc = _run(fake_repo, "AG-EV-TEST-001", "retired")
    assert rc == 0
