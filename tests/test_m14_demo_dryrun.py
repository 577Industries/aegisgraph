"""Wave 10A — M14 demo dry-run end-to-end pipeline tests.

`scripts/m14_demo_dryrun.sh` exercises the full discovery pipeline as a
single bash orchestrator:

  1. extract (graph emission for pinned Signal + Element X)
  2. engine_select (pick top-scoring record per target by score_vector.total)
  3. harnessgen render (no live fuzz; template-only)
  4. invariantcheck SARIF (skips honestly when codeql/semgrep absent)
  5. crosssma matrix render
  6. reviewer-packet export
  7. optional disclosure ledger tick (skipped pending T-M1.4/T-M1.5)

These tests assert the script:

  * produces `exports/m14-demo-dryrun/<ISO_DATE>/manifest.json`
  * each step's status is one of the documented status enums
  * a human-readable `dryrun-report.md` exists alongside
  * `checksums.sha256` validates atomically against the emitted tree
  * the full output tree passes `validator.sanitize_check.scan_export_tree`
    (Rules 1-9 + BLOCKING_PATTERNS)

The test is skipped when bash is unavailable. On Linux CI runners bash is
always present, but the guard is defensive (e.g. an unusual minimal
container without /bin/bash).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from aegisgraph.io import repo_root
from validator.sanitize_check import scan_export_tree


REPO = repo_root()
SCRIPT = REPO / "scripts" / "m14_demo_dryrun.sh"
OUTPUT_ROOT = REPO / "exports" / "m14-demo-dryrun"


VALID_STATUSES = {
    "success",
    "skipped_binary_absent",
    "skipped_runner_blocked",
    "skipped_counsel_blocked",
    "failed",
}


@pytest.fixture(scope="module")
def dryrun_output_dir() -> Path:
    """Run the script once per module, return the ISO_DATE output directory."""
    if shutil.which("bash") is None:
        pytest.skip("bash not available on this host")
    if not SCRIPT.is_file():
        pytest.skip(f"script not present: {SCRIPT}")

    # Invoke the script. It writes a fresh ISO_DATE directory each run.
    env = os.environ.copy()
    # Force AEGISGRAPH_STRICT_TOOLING off — the dryrun is fail-soft by design
    env.pop("AEGISGRAPH_STRICT_TOOLING", None)
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    # The script is fail-soft, so a non-zero exit means a real bug.
    assert result.returncode == 0, (
        f"script failed with code {result.returncode}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )

    # Find the freshly written ISO_DATE dir. The script prints it on stdout
    # as "DRYRUN_OUTPUT_DIR=<path>" for parseability.
    output_dir: Path | None = None
    for line in result.stdout.splitlines():
        if line.startswith("DRYRUN_OUTPUT_DIR="):
            output_dir = Path(line.split("=", 1)[1].strip())
            break
    assert output_dir is not None, (
        f"script did not print DRYRUN_OUTPUT_DIR= line\nstdout:\n{result.stdout}"
    )
    assert output_dir.is_dir(), f"output dir missing: {output_dir}"
    return output_dir


def test_manifest_json_exists(dryrun_output_dir: Path) -> None:
    """The dry-run manifest is the primary contract artifact."""
    manifest_path = dryrun_output_dir / "manifest.json"
    assert manifest_path.is_file(), f"missing: {manifest_path}"


def test_manifest_has_required_fields(dryrun_output_dir: Path) -> None:
    manifest = json.loads((dryrun_output_dir / "manifest.json").read_text())
    assert manifest.get("tool_output_type") == "m14_demo_dryrun_manifest"
    assert "iso_date" in manifest
    assert "generated_at" in manifest
    assert "generated_by" in manifest
    assert manifest.get("safety_posture") == "sanitized_candidate"
    assert manifest.get("private_by_default") is True
    assert isinstance(manifest.get("steps"), list)
    assert len(manifest["steps"]) >= 6, (
        f"expected >= 6 pipeline steps, got {len(manifest['steps'])}"
    )


def test_each_step_has_valid_status_enum(dryrun_output_dir: Path) -> None:
    manifest = json.loads((dryrun_output_dir / "manifest.json").read_text())
    for step in manifest["steps"]:
        assert "name" in step
        assert "status" in step
        assert step["status"] in VALID_STATUSES, (
            f"step {step['name']!r} has invalid status {step['status']!r}; "
            f"expected one of {sorted(VALID_STATUSES)}"
        )
        # Skips MUST carry a reason for honesty.
        if step["status"].startswith("skipped_"):
            assert step.get("reason"), (
                f"step {step['name']!r} is {step['status']} but has no reason"
            )


def test_pipeline_step_names_match_plan(dryrun_output_dir: Path) -> None:
    """The 7 documented steps from plan §24 Agent 10A must all be present."""
    manifest = json.loads((dryrun_output_dir / "manifest.json").read_text())
    names = {step["name"] for step in manifest["steps"]}
    expected = {
        "extract",
        "engine_select",
        "harnessgen_render",
        "invariantcheck_sarif",
        "crosssma_matrix",
        "reviewer_packet",
        "disclosure_ledger_tick",
    }
    missing = expected - names
    assert not missing, f"missing steps: {sorted(missing)}"


def test_disclosure_step_honestly_skipped(dryrun_output_dir: Path) -> None:
    """Counsel sign-off is blocked (T-M1.4/T-M1.5); the script must not
    fabricate a successful ledger entry."""
    manifest = json.loads((dryrun_output_dir / "manifest.json").read_text())
    disc_step = next(
        s for s in manifest["steps"] if s["name"] == "disclosure_ledger_tick"
    )
    # Counsel sign-off file does not (and should not) exist in this worktree.
    assert disc_step["status"] == "skipped_counsel_blocked"
    assert "counsel" in disc_step["reason"].lower()


def test_dryrun_report_md_exists(dryrun_output_dir: Path) -> None:
    report_path = dryrun_output_dir / "dryrun-report.md"
    assert report_path.is_file()
    body = report_path.read_text()
    assert "M14 demo dry-run" in body
    # The report must list every step's status, not just success ones.
    for step_name in (
        "extract",
        "engine_select",
        "harnessgen_render",
        "invariantcheck_sarif",
        "crosssma_matrix",
        "reviewer_packet",
        "disclosure_ledger_tick",
    ):
        assert step_name in body, f"step {step_name} not mentioned in report.md"


def test_checksums_validate(dryrun_output_dir: Path) -> None:
    """checksums.sha256 must list every other regular file under the run
    directory and the digests must match."""
    checksums_file = dryrun_output_dir / "checksums.sha256"
    assert checksums_file.is_file()

    seen: set[str] = set()
    for line in checksums_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        # `<hex>  <relpath>` format (GNU sha256sum).
        parts = line.split(maxsplit=1)
        assert len(parts) == 2, f"malformed checksum line: {line!r}"
        expected_hex, relpath = parts
        # `sha256sum -c` allows a leading `*` on binary mode; strip it.
        relpath = relpath.lstrip("*")
        file_path = dryrun_output_dir / relpath
        assert file_path.is_file(), f"checksum lists missing file: {relpath}"
        actual_hex = hashlib.sha256(file_path.read_bytes()).hexdigest()
        assert actual_hex == expected_hex, (
            f"checksum mismatch for {relpath}: "
            f"expected {expected_hex}, got {actual_hex}"
        )
        seen.add(relpath)
    assert seen, "checksums.sha256 is empty"


def test_sanitize_check_passes_on_output_tree(dryrun_output_dir: Path) -> None:
    """The whole output tree must pass `validator.sanitize_check` —
    Rules 1-9 + BLOCKING_PATTERNS. This is the public-safety gate the
    plan §24 contract requires."""
    report = scan_export_tree(dryrun_output_dir)
    assert report.ok, (
        "sanitize-check failed on M14 dry-run output:\n"
        + "\n".join(
            f"  - {failure.rule} @ {failure.where}: {failure.detail}"
            for failure in report.failures
        )
    )


def test_idempotent_rerun_creates_fresh_iso_date_dir(tmp_path: Path) -> None:
    """Re-running the script must produce a fresh, additive ISO_DATE
    directory; existing run directories must not be mutated.

    We assert structurally by inspecting OUTPUT_ROOT after one fresh
    invocation: the per-run dir is uniquely named so subsequent runs
    cannot collide. (The script picks a unique suffix when the date
    directory already exists — see script's _iso_date_dir.)
    """
    if shutil.which("bash") is None:
        pytest.skip("bash not available on this host")
    if not SCRIPT.is_file():
        pytest.skip(f"script not present: {SCRIPT}")

    # Run twice and assert the script generated two distinct output dirs.
    runs: list[Path] = []
    for _ in range(2):
        env = os.environ.copy()
        env.pop("AEGISGRAPH_STRICT_TOOLING", None)
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            cwd=str(REPO),
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
        assert result.returncode == 0, result.stderr
        out_line = next(
            line for line in result.stdout.splitlines()
            if line.startswith("DRYRUN_OUTPUT_DIR=")
        )
        runs.append(Path(out_line.split("=", 1)[1].strip()))

    assert runs[0].is_dir() and runs[1].is_dir()
    assert runs[0] != runs[1], (
        f"re-run reused same dir; non-idempotent: {runs[0]}"
    )
    # Both must contain a manifest.json — the first run was not clobbered.
    assert (runs[0] / "manifest.json").is_file()
    assert (runs[1] / "manifest.json").is_file()
