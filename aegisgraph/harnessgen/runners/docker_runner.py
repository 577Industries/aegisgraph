"""Subprocess wrapper for docker invocations.

This module is the seam between HarnessGen and the actual fuzz/build
execution. It does TWO things and only two:

  1. Builds a `docker run` command line from (image, cmd, mounts, env,
     timeout) and invokes it via subprocess.run.
  2. Translates subprocess outcomes into a `DockerResult` dataclass that
     the rest of HarnessGen consumes.

It is intentionally minimal — no daemon-mode, no `docker exec` into a
long-lived container, no image pulls. The image is assumed to exist on
the host already (the self-hosted runner is set up to have it).

`dry_run=True` synthesizes a stub result and DOES NOT invoke subprocess.
This is what CI smoke tests rely on; live docker is unavailable in CI.

Tests mock `subprocess.run`. The wrapper does NOT shell out via `shell=True`
— the docker CLI is invoked as an argv list, so user-supplied strings
can't inject shell metacharacters.
"""

from __future__ import annotations

import subprocess  # noqa: S404 — argv-only, no shell=True, see module docstring
import time
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class DockerResult:
    """Outcome of a docker invocation.

    `exit_code` is the subprocess return code. `stdout` and `stderr` are
    captured strings. `duration_seconds` is wall-clock time the wrapper
    spent in subprocess.run — useful for the coverage_collector's
    exec-per-sec extrapolation.
    """

    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    command: tuple[str, ...]


class DockerRunner:
    """Invokes docker via subprocess.

    Construct once per HarnessGen orchestration pass; reuse across runs.
    `dry_run=True` skips the subprocess entirely (used in CI smoke).
    """

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def run(
        self,
        image: str,
        cmd: Sequence[str],
        mounts: dict[str, str] | None = None,
        env: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> DockerResult:
        """Run `cmd` in `image`. Returns a DockerResult.

        On TimeoutExpired the result has exit_code=124 and "timeout"
        marker in stderr — the caller decides whether that's a failure
        or normal end-of-budget.
        """
        argv = self._build_argv(image=image, cmd=cmd, mounts=mounts, env=env)

        if self.dry_run:
            return DockerResult(
                exit_code=0,
                stdout="dry-run: docker invocation skipped\n",
                stderr="",
                duration_seconds=0.0,
                command=tuple(argv),
            )

        start = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 — argv-only; image+cmd are caller-controlled, not shell-interpreted
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return DockerResult(
                exit_code=124,
                stdout="",
                stderr=f"timeout after {timeout_seconds}s\n",
                duration_seconds=float(timeout_seconds or 0.0),
                command=tuple(argv),
            )
        duration = time.monotonic() - start
        return DockerResult(
            exit_code=int(completed.returncode),
            stdout=str(completed.stdout or ""),
            stderr=str(completed.stderr or ""),
            duration_seconds=duration,
            command=tuple(argv),
        )

    @staticmethod
    def _build_argv(
        image: str,
        cmd: Sequence[str],
        mounts: dict[str, str] | None,
        env: dict[str, str] | None,
    ) -> list[str]:
        """Assemble the docker argv. Keeps `run` lean for testability."""
        argv: list[str] = ["docker", "run", "--rm"]
        if mounts:
            for host, container in mounts.items():
                argv.extend(["-v", f"{host}:{container}"])
        if env:
            for key, value in env.items():
                argv.extend(["-e", f"{key}={value}"])
        argv.append(image)
        argv.extend(cmd)
        return argv


__all__ = ["DockerResult", "DockerRunner"]
