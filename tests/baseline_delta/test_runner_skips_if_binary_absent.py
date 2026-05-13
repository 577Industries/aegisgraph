"""Per-tool runner returns a `binary_missing` envelope when the
corresponding CLI binary is not on PATH.

Each per-tool runner in `aegisgraph.baseline_delta.runner` follows the
same convention used by `aegisgraph.invariants.runner.codeql_runner`:
binary-absent is NOT an error, it is a documented honest-output status
("binary_missing" or "skipped_pending_toolchain") so the test suite can
run on machines without CodeQL / Semgrep / Docker installed.

The runner functions accept a `which` callable (defaulting to
`shutil.which`) so the test can simulate binary absence without
manipulating PATH.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aegisgraph.baseline_delta.runner import (
    run_aegisgraph_alone,
    run_codeql_alone,
    run_mobsf_alone,
    run_semgrep_alone,
)


def _which_always_none(_binary: str) -> str | None:
    return None


def _make_target_spec(tmp_path: Path) -> dict[str, Any]:
    """Build a synthetic target spec the runner can consume.

    The runner does not need a real source tree to refuse-skip; it only
    needs the spec shape so the envelope it emits is well-formed.
    """
    return {
        "target_key": "signal",
        "target_id": "signal_android@1043851",
        "name": "Signal Android",
        "repo_url": "https://github.com/signalapp/Signal-Android",
        "commit": "1043851",
        "source_root": str(tmp_path / "src"),
        "codeql_db": str(tmp_path / "codeql-db"),
        "apk_path": None,
    }


def test_codeql_runner_returns_binary_missing_envelope_when_codeql_absent(tmp_path: Path) -> None:
    target = _make_target_spec(tmp_path)
    out_dir = tmp_path / "out"

    result = run_codeql_alone(
        target=target,
        output_dir=out_dir,
        which=_which_always_none,
    )

    assert result["tool"] == "codeql"
    assert result["status"] == "binary_missing"
    assert "codeql" in result["reason"].lower()
    assert result["sarif_path"] is None
    assert result["findings_count"] == 0


def test_semgrep_runner_returns_binary_missing_envelope_when_semgrep_absent(tmp_path: Path) -> None:
    target = _make_target_spec(tmp_path)
    out_dir = tmp_path / "out"

    result = run_semgrep_alone(
        target=target,
        output_dir=out_dir,
        which=_which_always_none,
    )

    assert result["tool"] == "semgrep"
    assert result["status"] == "binary_missing"
    assert "semgrep" in result["reason"].lower()
    assert result["sarif_path"] is None
    assert result["findings_count"] == 0


def test_mobsf_runner_returns_binary_missing_envelope_when_docker_absent(tmp_path: Path) -> None:
    target = _make_target_spec(tmp_path)
    out_dir = tmp_path / "out"

    result = run_mobsf_alone(
        target=target,
        output_dir=out_dir,
        which=_which_always_none,
    )

    assert result["tool"] == "mobsf"
    # When APK is absent the runner emits "apk_missing", which is a
    # different honest-output mode than "binary_missing". Both are
    # acceptable here — neither is an error.
    assert result["status"] in {"binary_missing", "apk_missing"}
    assert result["findings_count"] == 0


def test_mobsf_runner_returns_apk_missing_when_docker_present_but_no_apk(tmp_path: Path) -> None:
    """When docker is on PATH but no APK file is configured, MobSF emits
    apk_missing (NOT binary_missing). Per Wave 9A spec, APK absence must
    be transparent — runner writes MOBSF-LIMITED.md and returns the
    apk_missing envelope. No fabricated findings.
    """
    target = _make_target_spec(tmp_path)
    target["apk_path"] = None
    out_dir = tmp_path / "out"

    def _which_docker_only(binary: str) -> str | None:
        return "/usr/bin/docker" if binary == "docker" else None

    result = run_mobsf_alone(
        target=target,
        output_dir=out_dir,
        which=_which_docker_only,
    )

    assert result["tool"] == "mobsf"
    assert result["status"] == "apk_missing"
    assert result["findings_count"] == 0


def test_aegisgraph_runner_never_returns_binary_missing(tmp_path: Path) -> None:
    """AegisGraph itself has no external binary requirement — it consumes
    pre-existing extraction graphs + invariant manifest. Its runner
    returns a "scaffold_pending" or "ran" status, NEVER binary_missing.
    """
    target = _make_target_spec(tmp_path)
    out_dir = tmp_path / "out"

    result = run_aegisgraph_alone(
        target=target,
        output_dir=out_dir,
    )

    assert result["tool"] == "aegisgraph"
    assert result["status"] in {"ran", "scaffold_pending"}
    # No binary dependency means there is no reason to emit
    # "binary_missing" — assert this explicitly to lock the contract.
    assert result["status"] != "binary_missing"
