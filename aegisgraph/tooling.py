from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .constants import STATIC_GENERATED_AT
from .io import write_json


TOOL_COMMANDS = {
    "python": [sys.executable, "--version"],
    "make": ["make", "--version"],
    "git": ["git", "--version"],
    "semgrep": ["semgrep", "--version"],
    "codeql": ["codeql", "version", "--format=json"],
    "docker": ["docker", "--version"],
    "clang": ["clang", "--version"],
    "java": ["java", "-version"],
    "go": ["go", "version"],
    "rustc": ["rustc", "--version"],
}


def _version_for(command: list[str]) -> dict[str, Any]:
    executable = command[0]
    if executable != sys.executable and shutil.which(executable) is None:
        return {"available": False, "version": None, "note": "not found on PATH"}
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)
    except Exception as exc:
        return {"available": False, "version": None, "note": str(exc)}
    output = (completed.stdout or completed.stderr).strip()
    first_line = output.splitlines()[0] if output else ""
    return {
        "available": completed.returncode == 0,
        "version": first_line,
        "returncode": completed.returncode,
    }


def write_tooling_report(root: Path) -> dict[str, Any]:
    tools = {name: _version_for(command) for name, command in TOOL_COMMANDS.items()}
    report = {
        "tool_output_type": "tooling_versions",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "platform": {
            "python": sys.version,
            "system": platform.platform(),
        },
        "tools": tools,
        "notes": [
            "Phase 0 treats CodeQL, Semgrep, MobSF/Docker, Clang/libFuzzer, and language runtimes as required research tooling but non-blocking for the safe scaffold.",
            "A later hardening gate should promote selected tools from visible-missing to CI-blocking after the devcontainer is finalized.",
        ],
    }
    write_json(root / "tooling-versions.json", report)
    return report
