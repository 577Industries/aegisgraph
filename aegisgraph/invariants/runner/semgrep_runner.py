"""Semgrep CLI subprocess runner.

This module shells out to the `semgrep` CLI to run a rule (or a directory
of rules) against a source tree, producing SARIF.

Output: same `RunResult` shape as `codeql_runner.run_codeql`:
    {
      "status":  "ran" | "skipped_pending_toolchain" | "failed",
      "reason":  short human-readable note when skipped/failed,
      "sarif_path": str | None,
      "semgrep_version": raw version string from `semgrep --version`,
    }

Sanitize-check Rule 8 reminder: we do NOT extract code snippets from the
SARIF here — that responsibility lives in `sarif_consolidator.py` and the
consolidator already truncates `message` and drops snippets. The raw SARIF
file is kept on disk (engineering-private) and referenced by the
AG-IV-* record's `sarif_result_uri` field.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


SEMGREP_BIN = "semgrep"


def semgrep_available() -> bool:
    """Return True if a `semgrep` binary is on PATH."""
    return shutil.which(SEMGREP_BIN) is not None


def _semgrep_version() -> str | None:
    """Probe `semgrep --version`; return raw first line or None."""
    if not semgrep_available():
        return None
    try:
        completed = subprocess.run(
            [SEMGREP_BIN, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return None
    output = (completed.stdout or completed.stderr).strip()
    if not output:
        return None
    return output.splitlines()[0]


def run_semgrep(
    *,
    rules: Path,
    source: Path,
    output_sarif: Path,
    timeout_seconds: int = 1800,
) -> dict[str, Any]:
    """Run a Semgrep rule (or directory of rules) against a source tree.

    Args:
        rules:        path to a single .yaml rule file OR a directory of
                      .yaml rule files.
        source:       path to the source tree to scan.
        output_sarif: path the SARIF will be written to; parent dirs
                      are created if missing.
        timeout_seconds: subprocess timeout (default 30min).

    Returns:
        RunResult dict. See module docstring.
    """
    if not semgrep_available():
        return {
            "status": "skipped_pending_toolchain",
            "reason": "semgrep CLI not on PATH",
            "sarif_path": None,
            "semgrep_version": None,
        }

    if not rules.exists():
        return {
            "status": "failed",
            "reason": f"semgrep rules path not found at {rules}",
            "sarif_path": None,
            "semgrep_version": _semgrep_version(),
        }
    if not source.exists():
        return {
            "status": "failed",
            "reason": f"semgrep source path not found at {source}",
            "sarif_path": None,
            "semgrep_version": _semgrep_version(),
        }

    output_sarif.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        SEMGREP_BIN,
        "scan",
        f"--config={rules}",
        "--sarif",
        f"--output={output_sarif}",
        # Don't try to phone home to semgrep.dev in CI/sandboxed envs.
        "--metrics=off",
        # Quiet noise so failure output is interpretable.
        "--quiet",
        str(source),
    ]

    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:  # pragma: no cover
        return {
            "status": "failed",
            "reason": f"semgrep scan timed out after {timeout_seconds}s",
            "sarif_path": None,
            "semgrep_version": _semgrep_version(),
        }
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        return {
            "status": "failed",
            "reason": f"semgrep scan failed: {exc}",
            "sarif_path": None,
            "semgrep_version": _semgrep_version(),
        }

    # Semgrep uses exit code 1 to indicate "findings present" (not an error)
    # and 2+ for real failures. So we treat 0 and 1 as "ran".
    if completed.returncode not in (0, 1):
        return {
            "status": "failed",
            "reason": (
                f"semgrep scan exit={completed.returncode}: "
                f"{(completed.stderr or completed.stdout)[:200]}"
            ),
            "sarif_path": None,
            "semgrep_version": _semgrep_version(),
        }

    return {
        "status": "ran",
        "reason": None,
        "sarif_path": str(output_sarif),
        "semgrep_version": _semgrep_version(),
    }


__all__ = ["run_semgrep", "semgrep_available"]
