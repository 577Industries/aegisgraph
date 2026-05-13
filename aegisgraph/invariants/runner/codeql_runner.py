"""CodeQL CLI subprocess runner.

This module shells out to the `codeql` CLI to:

  1. Run a single .ql query (or a qlpack) against a pre-built CodeQL
     database; OR
  2. Verify the binary is on PATH at a supported version.

We do NOT build the CodeQL database here — that's an extraction-layer
concern; this runner consumes a database directory built by
`extraction/codeql/*` or the M3.3 ground-truth fixture builder.

Output: a `RunResult` dict carrying:
    {
      "status":  "ran" | "skipped_pending_toolchain" | "failed",
      "reason":  short human-readable note when skipped/failed,
      "sarif_path": path to the SARIF output (string) if status == "ran",
      "codeql_version": raw version string from `codeql version`,
    }

`status == "skipped_pending_toolchain"` is NOT an error — it is the
documented honest-output mode for environments without CodeQL installed.
The consolidator just gets an empty record list in that case.

Tests should NEVER require the codeql binary to be present:

    @pytest.mark.skipif(
        not shutil.which("codeql"),
        reason="codeql CLI not installed in test environment",
    )
    def test_live_codeql_runs(...): ...

For everything else, tests feed a synthetic SARIF dict directly to
`aegisgraph.invariants.runner.sarif_consolidator.consolidate_sarif`.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


CODEQL_BIN = "codeql"


def codeql_available() -> bool:
    """Return True if a `codeql` binary is on PATH."""
    return shutil.which(CODEQL_BIN) is not None


def _codeql_version() -> str | None:
    """Probe `codeql version --format=text`; return raw first line or None."""
    if not codeql_available():
        return None
    try:
        completed = subprocess.run(
            [CODEQL_BIN, "version", "--format=text"],
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


def run_codeql(
    *,
    database: Path,
    query: Path,
    output_sarif: Path,
    timeout_seconds: int = 1800,
) -> dict[str, Any]:
    """Run a single CodeQL query against a pre-built database.

    Args:
        database:       path to a CodeQL database directory (e.g.
                        `extraction/codeql/databases/demo-vulnerable-app/`).
        query:          path to a single .ql file.
        output_sarif:   path the SARIF will be written to; parent
                        directories are created if missing.
        timeout_seconds: subprocess timeout (default 30min).

    Returns:
        RunResult dict. See module docstring. Never raises on normal
        flow — bin-absent and run-failure are both returned as status
        codes, NOT exceptions.
    """
    if not codeql_available():
        return {
            "status": "skipped_pending_toolchain",
            "reason": "codeql CLI not on PATH",
            "sarif_path": None,
            "codeql_version": None,
        }

    if not database.is_dir():
        return {
            "status": "failed",
            "reason": f"CodeQL database not found at {database}",
            "sarif_path": None,
            "codeql_version": _codeql_version(),
        }
    if not query.is_file():
        return {
            "status": "failed",
            "reason": f"query file not found at {query}",
            "sarif_path": None,
            "codeql_version": _codeql_version(),
        }

    output_sarif.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        CODEQL_BIN,
        "database",
        "analyze",
        str(database),
        str(query),
        "--format=sarifv2.1.0",
        f"--output={output_sarif}",
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
            "reason": f"codeql analyze timed out after {timeout_seconds}s",
            "sarif_path": None,
            "codeql_version": _codeql_version(),
        }
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        return {
            "status": "failed",
            "reason": f"codeql analyze failed: {exc}",
            "sarif_path": None,
            "codeql_version": _codeql_version(),
        }

    if completed.returncode != 0:
        return {
            "status": "failed",
            "reason": (
                f"codeql analyze exit={completed.returncode}: "
                f"{(completed.stderr or completed.stdout)[:200]}"
            ),
            "sarif_path": None,
            "codeql_version": _codeql_version(),
        }

    return {
        "status": "ran",
        "reason": None,
        "sarif_path": str(output_sarif),
        "codeql_version": _codeql_version(),
    }


__all__ = ["run_codeql", "codeql_available"]
