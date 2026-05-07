"""Strict-tooling tests.

Verifies that `validator.cli strict-tooling --required clang` exits 1 when
`clang` is hidden from PATH (typical CI runner environment without the
devcontainer pinned tools), and that an empty/unknown --required value
returns the right exit codes.

We sandbox the test with a private PATH that excludes `clang`. Python
itself stays available because we use sys.executable directly.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _python_only_path() -> str:
    """Return a PATH that contains the python binary's directory only.

    This is a portable way to ensure clang/codeql/semgrep are NOT on PATH
    while still allowing the subprocess to exec python correctly.
    """
    py_dir = str(Path(sys.executable).resolve().parent)
    return py_dir


def test_strict_tooling_fails_when_clang_hidden() -> None:
    env = dict(os.environ)
    env["PATH"] = _python_only_path()
    env["AEGISGRAPH_STRICT_TOOLING"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "validator.cli",
            "strict-tooling",
            "--required",
            "clang",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 1, (result.returncode, result.stdout, result.stderr)
    assert "FAIL" in result.stdout
    assert "clang" in result.stdout.lower()


def test_strict_tooling_fails_when_multiple_tools_hidden() -> None:
    env = dict(os.environ)
    env["PATH"] = _python_only_path()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "validator.cli",
            "strict-tooling",
            "--required",
            "clang,codeql,semgrep,docker",
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 1
    out = result.stdout.lower()
    # All four should be reported missing (or below-min) in some form.
    for tool in ("clang", "codeql", "semgrep", "docker"):
        assert tool in out, f"tool {tool!r} not reported in output: {out!r}"


def test_strict_tooling_unknown_tool_is_reported() -> None:
    """If --required lists a name not in REQUIRED_TOOLS, we fail with an
    UNKNOWN line, not silently pass.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "validator.cli",
            "strict-tooling",
            "--required",
            "not-a-real-tool",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "UNKNOWN" in result.stdout or "FAIL" in result.stdout


def test_strict_tooling_empty_required_returns_2() -> None:
    """No --required tool list => usage error (exit 2)."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "validator.cli",
            "strict-tooling",
            "--required",
            "",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    err = (result.stderr + result.stdout).lower()
    assert "required" in err
