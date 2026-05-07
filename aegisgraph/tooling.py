from __future__ import annotations

import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .constants import STATIC_GENERATED_AT
from .io import write_json


# ---------------------------------------------------------------------------
# Tool inventory
# ---------------------------------------------------------------------------
#
# REQUIRED_TOOLS is the authoritative table of versioned tools needed for the
# AegisGraph Tier 3 reproduce/extract/sanitize pipelines. The table is
# enforced when the user passes --strict (or sets AEGISGRAPH_STRICT_TOOLING=1)
# via `aegisgraph tooling --strict` -- which `make tooling-strict` and
# `make reproduce` both call before doing real work.
#
# When you bump a pinned version in devcontainer/Dockerfile, bump it here too.
# Mismatch is intentional drift and will fail-closed in strict mode.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RequiredTool:
    name: str
    min_version: str
    check_command: tuple[str, ...]
    # Human-readable note about WHY this tool is required.
    purpose: str


# Order matters only for human-readable reports. Strict-mode enforcement is
# all-or-nothing: any required tool missing or below min_version fails-closed.
REQUIRED_TOOLS: tuple[RequiredTool, ...] = (
    RequiredTool(
        name="python3",
        min_version="3.11.0",
        check_command=(sys.executable, "--version"),
        purpose="aegisgraph CLI runtime; matches pyproject.requires-python",
    ),
    RequiredTool(
        name="clang",
        min_version="18.0.0",
        check_command=("clang", "--version"),
        purpose="reprochain libwebp ASAN+libFuzzer harness build",
    ),
    RequiredTool(
        name="codeql",
        min_version="2.20.6",
        check_command=("codeql", "version", "--format=json"),
        purpose="extraction CodeQL static analysis (Java + Python packs)",
    ),
    RequiredTool(
        name="semgrep",
        min_version="1.86.0",
        check_command=("semgrep", "--version"),
        purpose="extraction Semgrep rule scans on Signal/Element-X anchors",
    ),
    RequiredTool(
        name="docker",
        min_version="24.0.0",
        check_command=("docker", "--version"),
        purpose="MobSF runner (extract --deep) + reprochain reproducible builds",
    ),
    RequiredTool(
        name="java",
        min_version="21.0.0",
        check_command=("java", "-version"),
        purpose="CodeQL Java packs + Android source extraction",
    ),
    RequiredTool(
        name="go",
        min_version="1.22.5",
        check_command=("go", "version"),
        purpose="polydiff Go net/url parser corpus builds",
    ),
    RequiredTool(
        name="rustc",
        min_version="1.79.0",
        check_command=("rustc", "--version"),
        purpose="polydiff rust-url parser corpus builds",
    ),
    RequiredTool(
        name="node",
        min_version="20.0.0",
        check_command=("node", "--version"),
        purpose="polydiff JS parser corpus + extraction adapters",
    ),
)


# ---------------------------------------------------------------------------
# All tools to probe (REQUIRED + a few helpful diagnostics)
# ---------------------------------------------------------------------------

TOOL_COMMANDS: dict[str, list[str]] = {
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
    "node": ["node", "--version"],
}


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------


def _version_for(command: list[str] | tuple[str, ...]) -> dict[str, Any]:
    """Probe a tool: returns {available, version (raw first line), returncode, note?}."""
    cmd = list(command)
    executable = cmd[0]
    if executable != sys.executable and shutil.which(executable) is None:
        return {"available": False, "version": None, "note": "not found on PATH"}
    try:
        completed = subprocess.run(
            cmd, check=False, capture_output=True, text=True, timeout=10
        )
    except Exception as exc:  # pragma: no cover - subprocess failure path
        return {"available": False, "version": None, "note": str(exc)}
    output = (completed.stdout or completed.stderr).strip()
    first_line = output.splitlines()[0] if output else ""
    return {
        "available": completed.returncode == 0,
        "version": first_line,
        "returncode": completed.returncode,
    }


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3})")


def _parse_version(text: str | None) -> tuple[int, ...] | None:
    """Extract first dotted version tuple from a free-form version string."""
    if not text:
        return None
    match = _VERSION_RE.search(text)
    if not match:
        return None
    parts = match.group(1).split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:  # pragma: no cover
        return None


def _meets_min(observed: str | None, minimum: str) -> bool:
    obs = _parse_version(observed)
    minv = _parse_version(minimum)
    if obs is None or minv is None:
        return False
    # Pad the shorter tuple with zeros so 1.22 >= 1.22.0.
    length = max(len(obs), len(minv))
    obs_padded = obs + (0,) * (length - len(obs))
    minv_padded = minv + (0,) * (length - len(minv))
    return obs_padded >= minv_padded


# ---------------------------------------------------------------------------
# Strict gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StrictResult:
    ok: bool
    missing: tuple[str, ...]
    below_min: tuple[tuple[str, str, str], ...]  # (name, observed, required)


def evaluate_strict(probed: dict[str, dict[str, Any]]) -> StrictResult:
    """Evaluate REQUIRED_TOOLS against a probed-tools dict (from write_tooling_report)."""
    missing: list[str] = []
    below: list[tuple[str, str, str]] = []
    for required in REQUIRED_TOOLS:
        # The probed dict keys come from TOOL_COMMANDS, where python lives at
        # key "python" not "python3". Map gracefully.
        key = required.name if required.name in probed else (
            "python" if required.name == "python3" else required.name
        )
        info = probed.get(key)
        if info is None or not info.get("available"):
            missing.append(required.name)
            continue
        version_text = info.get("version")
        if not _meets_min(version_text, required.min_version):
            below.append((required.name, version_text or "", required.min_version))
    return StrictResult(
        ok=not missing and not below,
        missing=tuple(missing),
        below_min=tuple(below),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def write_tooling_report(root: Path) -> dict[str, Any]:
    tools = {name: _version_for(command) for name, command in TOOL_COMMANDS.items()}
    strict = evaluate_strict(tools)
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
        "required_tools": [
            {
                "name": t.name,
                "min_version": t.min_version,
                "purpose": t.purpose,
                "check_command": list(t.check_command),
            }
            for t in REQUIRED_TOOLS
        ],
        "strict_evaluation": {
            "ok": strict.ok,
            "missing": list(strict.missing),
            "below_min": [
                {"name": name, "observed": obs, "required_min": req}
                for (name, obs, req) in strict.below_min
            ],
        },
        "notes": [
            "Strict mode is gated by --strict or AEGISGRAPH_STRICT_TOOLING=1.",
            "REQUIRED_TOOLS table is the authority. devcontainer/Dockerfile pins must agree.",
            "make reproduce calls `tooling-strict` first (fail-closed) before extract/reprochain/polydiff/smabench.",
        ],
    }
    write_json(root / "tooling-versions.json", report)
    return report


def strict_summary_lines(report: dict[str, Any]) -> list[str]:
    """Render the strict_evaluation block as a human-readable list of lines."""
    strict = report.get("strict_evaluation", {})
    if strict.get("ok"):
        return ["all required tools present and at or above min versions"]
    lines: list[str] = []
    for name in strict.get("missing", []):
        lines.append(f"  MISSING: {name}")
    for entry in strict.get("below_min", []):
        lines.append(
            f"  BELOW MIN: {entry['name']} observed={entry['observed']!r} required>={entry['required_min']}"
        )
    return lines
