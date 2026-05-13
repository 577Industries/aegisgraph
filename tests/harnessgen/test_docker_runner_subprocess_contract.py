"""Docker runner subprocess contract — subprocess MOCKED.

The docker_runner module is the seam between HarnessGen and the actual
fuzz/build execution that happens (eventually) inside a docker container
on a self-hosted runner. M3.1 ships the wrapper only; live invocation is
deferred. These tests pin the *contract* the wrapper exposes:

  * `run(image, cmd, mounts, env, timeout_seconds)` returns a `DockerResult`
    with `.exit_code`, `.stdout`, `.stderr`, `.duration_seconds`.
  * The wrapper invokes `subprocess.run` (or .Popen) — never bypassed.
  * `dry_run=True` returns a synthesized "would-have-run" result without
    invoking subprocess at all (useful for CI smoke tests).
  * No live network egress is implied; the wrapper does not pull images,
    that's a pre-step the runner image must already have.

All subprocess calls are MOCKED in this test module. No `docker` binary
needs to be installed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aegisgraph.harnessgen.runners.docker_runner import (
    DockerResult,
    DockerRunner,
)


def _make_completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> MagicMock:
    """Build a stand-in for subprocess.CompletedProcess."""
    completed = MagicMock()
    completed.returncode = returncode
    completed.stdout = stdout
    completed.stderr = stderr
    return completed


def test_runner_returns_docker_result() -> None:
    runner = DockerRunner()
    with patch(
        "aegisgraph.harnessgen.runners.docker_runner.subprocess.run",
        return_value=_make_completed(stdout="ok\n", returncode=0),
    ) as mocked:
        result = runner.run(
            image="aegis-harness:latest",
            cmd=["echo", "hello"],
        )
    assert isinstance(result, DockerResult)
    assert result.exit_code == 0
    assert "ok" in result.stdout
    assert mocked.called


def test_runner_propagates_nonzero_exit() -> None:
    runner = DockerRunner()
    with patch(
        "aegisgraph.harnessgen.runners.docker_runner.subprocess.run",
        return_value=_make_completed(stderr="boom\n", returncode=137),
    ):
        result = runner.run(
            image="aegis-harness:latest",
            cmd=["false"],
        )
    assert result.exit_code == 137
    assert "boom" in result.stderr


def test_runner_invokes_docker_binary() -> None:
    runner = DockerRunner()
    with patch(
        "aegisgraph.harnessgen.runners.docker_runner.subprocess.run",
        return_value=_make_completed(),
    ) as mocked:
        runner.run(
            image="aegis-harness:latest",
            cmd=["echo", "hi"],
        )
    args, kwargs = mocked.call_args
    invoked = args[0] if args else kwargs.get("args")
    assert invoked[0] == "docker"
    assert "run" in invoked
    assert "aegis-harness:latest" in invoked


def test_runner_passes_mounts() -> None:
    runner = DockerRunner()
    with patch(
        "aegisgraph.harnessgen.runners.docker_runner.subprocess.run",
        return_value=_make_completed(),
    ) as mocked:
        runner.run(
            image="aegis-harness:latest",
            cmd=["echo", "hi"],
            mounts={"/host/src": "/work/src"},
        )
    invoked = mocked.call_args[0][0]
    joined = " ".join(invoked)
    assert "/host/src:/work/src" in joined


def test_runner_passes_env() -> None:
    runner = DockerRunner()
    with patch(
        "aegisgraph.harnessgen.runners.docker_runner.subprocess.run",
        return_value=_make_completed(),
    ) as mocked:
        runner.run(
            image="aegis-harness:latest",
            cmd=["echo", "hi"],
            env={"FUZZ_BUDGET": "60"},
        )
    invoked = mocked.call_args[0][0]
    joined = " ".join(invoked)
    assert "FUZZ_BUDGET=60" in joined


def test_runner_dry_run_skips_subprocess() -> None:
    """In dry_run mode the wrapper synthesizes a zero-exit result and
    DOES NOT call subprocess. This is what `make harnessgen-native`
    uses for CI smoke checks."""
    runner = DockerRunner(dry_run=True)
    with patch(
        "aegisgraph.harnessgen.runners.docker_runner.subprocess.run"
    ) as mocked:
        result = runner.run(
            image="aegis-harness:latest",
            cmd=["fuzz", "--budget", "60"],
        )
    assert result.exit_code == 0
    assert "dry-run" in result.stdout.lower()
    assert not mocked.called


def test_runner_timeout_propagates() -> None:
    """If subprocess raises TimeoutExpired, the wrapper returns a result
    with exit_code != 0 and a documented stderr marker. The exception is
    NOT re-raised — fuzzing timeouts are normal and the caller decides."""
    import subprocess as sp

    runner = DockerRunner()
    with patch(
        "aegisgraph.harnessgen.runners.docker_runner.subprocess.run",
        side_effect=sp.TimeoutExpired(cmd="docker run", timeout=1),
    ):
        result = runner.run(
            image="aegis-harness:latest",
            cmd=["fuzz"],
            timeout_seconds=1,
        )
    assert result.exit_code != 0
    assert "timeout" in result.stderr.lower()
