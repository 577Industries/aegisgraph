"""Export contract tests, owned by the integration stream.

Two contracts under test:

1. `export_public_sanitized` ALWAYS emits release_authorized=False until the
   validator-export sanitize check is wired. Even with the env override set,
   this stream's _sanitize_check_passes stub returns False, so the gate
   stays closed.

2. `export_public_sanitized(dry_run=True)` writes nothing to disk under
   exports/public-sanitized/manifest.json or polydiff_regression_report.sanitized.json,
   but returns a complete manifest. Reviewers can inspect the manifest
   fields (artifact list, release_authorized, release_note, validation_status)
   without mutating the export tree.

3. `export_private` continues to write the private-submission manifest with
   the full artifact list when input artifacts exist. Coverage of the private
   export path is intentionally narrower than the public path; the public
   path is the one with the human gate.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from aegisgraph.export import (
    ENV_RELEASE_AUTHORIZED,
    export_private,
    export_public_sanitized,
)
from aegisgraph.extraction import run_extract
from aegisgraph.polydiff import run_regression
from aegisgraph.reprochain import map_targets


def _seed_repo(tmp_path: Path) -> None:
    shutil.copytree("schema", tmp_path / "schema")
    run_extract(tmp_path)
    map_targets(tmp_path)
    run_regression(tmp_path)


def test_public_sanitized_release_authorized_is_false_default(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    manifest = export_public_sanitized(tmp_path)
    assert manifest["release_authorized"] is False
    assert "Human authorization gate" in manifest["release_note"] or \
           "release_authorized stays False" in manifest["release_note"]


def test_public_sanitized_release_authorized_stays_false_with_env_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Setting AEGISGRAPH_RELEASE_AUTHORIZED=1 alone is NOT sufficient.
    The validator/sanitize_check must also pass. Pre-poison the export
    tree so the wired sanitize_check (ADR 0021) trips a forbidden-content
    rule and the gate stays closed."""
    _seed_repo(tmp_path)
    public_dir = tmp_path / "exports" / "public-sanitized"
    public_dir.mkdir(parents=True, exist_ok=True)
    # Plant a forbidden-content file so rule 1 (BEGIN PRIVATE KEY) trips.
    (public_dir / "leaked_key.txt").write_text(
        "-----BEGIN PRIVATE KEY-----\nMIIEvA\n-----END PRIVATE KEY-----\n"
    )
    monkeypatch.setenv(ENV_RELEASE_AUTHORIZED, "1")
    manifest = export_public_sanitized(tmp_path)
    assert manifest["release_authorized"] is False
    # Note must call out that the env was set but the sanitize check failed.
    assert "validator/sanitize_check.py" in manifest["release_note"]


def test_public_sanitized_release_authorized_true_with_clean_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With env=1 AND a sanitize-clean export tree, the gate flips True.
    Verifies the validator.sanitize_check wiring (ADR 0021) actually
    enables the human-authorized release path. The minimal sanitized
    polydiff report written by export_public_sanitized passes all
    sanitize_check rules in a fresh tmp tree."""
    _seed_repo(tmp_path)
    monkeypatch.setenv(ENV_RELEASE_AUTHORIZED, "1")
    manifest = export_public_sanitized(tmp_path)
    assert manifest["release_authorized"] is True
    assert "Both environment authorization and sanitize-check passed" in manifest["release_note"]


def test_public_sanitized_dry_run_writes_no_files(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    public_dir = tmp_path / "exports" / "public-sanitized"
    # Snapshot pre-state: the directory may or may not exist; if a sibling
    # extraction step created it, capture file list for diff after.
    pre = sorted(p.relative_to(tmp_path) for p in public_dir.rglob("*")) if public_dir.exists() else []

    manifest = export_public_sanitized(tmp_path, dry_run=True)
    assert manifest["dry_run"] is True
    assert manifest["release_authorized"] is False

    post = sorted(p.relative_to(tmp_path) for p in public_dir.rglob("*")) if public_dir.exists() else []
    assert pre == post, f"dry_run mutated exports/public-sanitized/: pre={pre} post={post}"
    # Specifically: no manifest.json on disk after dry_run.
    assert not (public_dir / "manifest.json").exists()


def test_public_sanitized_real_run_writes_manifest(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    manifest = export_public_sanitized(tmp_path, dry_run=False)
    on_disk = tmp_path / "exports" / "public-sanitized" / "manifest.json"
    assert on_disk.exists()
    assert manifest["dry_run"] is False
    # Sanitized polydiff report should also be on disk now.
    sanitized = tmp_path / "exports" / "public-sanitized" / "polydiff_regression_report.sanitized.json"
    assert sanitized.exists()


def test_private_export_includes_validation_status(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    manifest = export_private(tmp_path)
    assert manifest["validation_status"] in {"pass", "fail"}
    assert "artifacts" in manifest
    on_disk = tmp_path / "exports" / "private-submission" / "manifest.json"
    assert on_disk.exists()


def test_private_export_excludes_corpora_private(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    manifest = export_private(tmp_path)
    excluded = manifest.get("excluded", [])
    assert any("reprochain/corpora-private" in entry for entry in excluded), excluded
    assert any("raw target source" in entry.lower() for entry in excluded), excluded
    assert any("credentials" in entry.lower() for entry in excluded), excluded
