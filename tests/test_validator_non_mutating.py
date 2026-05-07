"""Non-mutating validator tests.

Verifies that `validator.cli validate --non-mutating` returns the same
report shape as the mutating run BUT does not write
validation-report.json. We do this in a tmp_path that mirrors the repo
layout (schema/ dir + minimal evidence) so we don't disturb the actual
checked-in validation-report.json.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest

from aegisgraph.extraction import run_extract
from aegisgraph.polydiff import run_regression
from aegisgraph.reprochain import map_targets

from validator.validate_evidence import (
    ENV_NON_MUTATING,
    run,
    validate_repo_non_mutating,
)


def _seed_repo(tmp_path: Path) -> None:
    shutil.copytree("schema", tmp_path / "schema")
    run_extract(tmp_path)
    map_targets(tmp_path)
    run_regression(tmp_path)


def test_non_mutating_returns_same_status_as_mutating(tmp_path: Path) -> None:
    """Both modes must agree on status, schema_errors, records_checked."""
    _seed_repo(tmp_path)
    non_mut = validate_repo_non_mutating(tmp_path)
    # Now do the mutating run in the same tmp dir.
    from aegisgraph.validation import validate_repo

    mut = validate_repo(tmp_path)
    assert non_mut["status"] == mut["status"]
    assert non_mut["records_checked"] == mut["records_checked"]
    assert non_mut["schema_errors"] == mut["schema_errors"]
    # Records may differ in iteration order but should have the same length.
    assert len(non_mut["record_results"]) == len(mut["record_results"])


def test_non_mutating_does_not_write_validation_report(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    target = tmp_path / "validation-report.json"
    assert not target.exists()
    report = validate_repo_non_mutating(tmp_path)
    assert report["status"] in {"pass", "fail"}
    assert not target.exists(), "non-mutating mode wrote validation-report.json"


def test_non_mutating_does_not_change_existing_report_mtime(
    tmp_path: Path,
) -> None:
    """If validation-report.json already exists, --non-mutating must not
    touch its mtime."""
    _seed_repo(tmp_path)
    # Pre-seed a report file with a known timestamp.
    target = tmp_path / "validation-report.json"
    target.write_text(json.dumps({"sentinel": "do not touch"}), encoding="utf-8")
    pre_mtime = target.stat().st_mtime
    pre_content = target.read_text()

    # Run via the run() public entry to also exercise that wrapper.
    time.sleep(0.05)  # ensure any accidental write would change mtime
    report = run(non_mutating=True, root=tmp_path)
    assert report["status"] in {"pass", "fail"}

    post_mtime = target.stat().st_mtime
    post_content = target.read_text()
    assert post_mtime == pre_mtime, (
        f"non-mutating mode changed file mtime: pre={pre_mtime} post={post_mtime}"
    )
    assert post_content == pre_content


def test_env_var_triggers_non_mutating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_repo(tmp_path)
    monkeypatch.setenv(ENV_NON_MUTATING, "1")
    target = tmp_path / "validation-report.json"
    assert not target.exists()
    report = run(non_mutating=False, root=tmp_path)  # flag False, env=1
    assert report["status"] in {"pass", "fail"}
    assert not target.exists(), "env-triggered non-mutating mode wrote file"


def test_mutating_writes_report_for_baseline(tmp_path: Path) -> None:
    """Sanity: the mutating run DOES write the file (so the contrast test
    above is meaningful)."""
    _seed_repo(tmp_path)
    target = tmp_path / "validation-report.json"
    assert not target.exists()
    run(non_mutating=False, root=tmp_path)
    assert target.exists()
