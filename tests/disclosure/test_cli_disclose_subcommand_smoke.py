"""Smoke tests for `aegisgraph disclose` subcommand.

Three sub-subcommands:
  ledger --verify : exit 0 when chain intact, non-zero otherwise
  status          : human-readable summary of ledger
  tick            : embargo timer cron callable; emits next-action JSON
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from aegisgraph import cli
from aegisgraph.disclosure import ledger as disclosure_ledger


def _event(finding_id: str = "AG-DIS-IMG-0001") -> dict:
    return {
        "entry_id": "AG-DISC-20260612-CLIA",
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
            "generated_by": "test_cli",
            "generated_at": "2026-05-12T00:00:00Z",
            "source": "tests/disclosure/test_cli_disclose_subcommand_smoke.py",
            "private_by_default": True,
        },
        "safety_flags": [],
    }


def test_disclose_ledger_verify_passes_on_empty_real_ledger() -> None:
    """The production ledger is empty in M1; verify must exit 0."""
    result = subprocess.run(
        [sys.executable, "-m", "aegisgraph.cli", "disclose", "ledger", "--verify"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_disclose_status_exits_zero(capsys) -> None:
    """status prints a human-readable summary and returns 0."""
    rc = cli.main(["disclose", "status"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "ledger" in captured.out.lower()


def test_disclose_tick_emits_json(tmp_path: Path, capsys) -> None:
    """`tick --ledger-path <p> --as-of YYYY-MM-DD` reads the ledger and
    prints a JSON array of {finding_id, next_action_date, ...}."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(_event(), path=ledger_path)

    rc = cli.main(
        [
            "disclose",
            "tick",
            "--ledger-path",
            str(ledger_path),
            "--as-of",
            "2026-06-12",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert isinstance(payload, list)
    assert payload[0]["finding_id"] == "AG-DIS-IMG-0001"
    assert payload[0]["next_action_date"] == "2026-09-10"


def test_disclose_ledger_verify_with_custom_path(tmp_path: Path) -> None:
    """`disclose ledger --verify --ledger-path <p>` accepts a custom path
    so the workflow can verify pre-commit ledgers."""
    ledger_path = tmp_path / "ledger.jsonl"
    disclosure_ledger.append(_event(), path=ledger_path)
    rc = cli.main(
        [
            "disclose",
            "ledger",
            "--verify",
            "--ledger-path",
            str(ledger_path),
        ]
    )
    assert rc == 0
