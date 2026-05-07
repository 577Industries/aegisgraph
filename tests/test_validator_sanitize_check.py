"""Sanitize-check tests.

Verifies that:
  - The clean-export fixture passes (exit 0).
  - The corrupted-export fixture trips multiple rules (exit 1).
  - is_export_safe(missing_path) is False (fail-closed for missing trees).
  - Empty directories fail closed.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from validator.sanitize_check import (
    Failure,
    ScanReport,
    is_export_safe,
    main,
    scan_export_tree,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures"
CLEAN = FIXTURES / "clean-export"
CORRUPT = FIXTURES / "corrupted-export"


def test_clean_fixture_passes() -> None:
    report = scan_export_tree(CLEAN)
    assert report.ok, _format_failures(report)
    assert report.files_scanned >= 2  # manifest.json + polydiff sanitized


def test_corrupted_fixture_fails_with_multiple_rules() -> None:
    report = scan_export_tree(CORRUPT)
    assert not report.ok
    rules = {f.rule for f in report.failures}
    # We expect at least these rules to fire (the corrupted fixture is
    # designed to violate several at once):
    expected_subset = {
        "pem_private_key",  # BEGIN ... PRIVATE KEY block
        "api_key_token",  # api_key= ...
        "linux_home",  # /home/founder/...
        "private_submission",  # exports/private-submission/...
        "novel_private_candidate_in_public",
        "accepted_with_private_disclosure",
        "static_only_promoted_to_accepted",
        "embedded_crash_payload",
        "tool_output_wrong_safety_posture",
    }
    assert expected_subset.issubset(rules), (
        f"missing rules: {expected_subset - rules}; got: {rules}"
    )


def test_clean_fixture_via_module_main(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main([str(CLEAN)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PASS" in out


def test_corrupted_fixture_via_module_main(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = main([str(CORRUPT)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAIL" in out


def test_is_export_safe_missing_path() -> None:
    """A non-existent path is fail-closed (False)."""
    assert is_export_safe(Path("/nonexistent/path/that/does/not/exist")) is False


def test_is_export_safe_clean(tmp_path: Path) -> None:
    target = tmp_path / "snap"
    shutil.copytree(CLEAN, target)
    assert is_export_safe(target) is True


def test_empty_dir_fails_closed(tmp_path: Path) -> None:
    """An empty export directory must NOT be certified safe."""
    target = tmp_path / "empty-export"
    target.mkdir()
    report = scan_export_tree(target)
    assert not report.ok
    assert any(f.rule == "empty_export_tree" for f in report.failures)


def test_pem_private_key_rule_in_subprocess() -> None:
    """End-to-end: sanitize-check via `python -m validator.cli sanitize-check
    <corrupted>` exits 1 and prints rule names.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "validator.cli",
            "sanitize-check",
            str(CORRUPT),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, (result.returncode, result.stdout, result.stderr)
    assert "FAIL" in result.stdout
    assert "pem_private_key" in result.stdout or "BEGIN" in result.stdout.lower()


def test_clean_via_subprocess() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "validator.cli", "sanitize-check", str(CLEAN)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert "PASS" in result.stdout


def _format_failures(report: ScanReport) -> str:
    return "\n".join(f.to_line() for f in report.failures)
