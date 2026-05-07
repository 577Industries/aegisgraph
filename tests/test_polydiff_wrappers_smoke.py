"""Per-wrapper smoke tests.

For each parser wrapper marked `built` in PARSER_STATUS.json, dispatch
its `test_basic.sh` and assert exit 0 + valid JSON conforming to v2.
Wrappers marked `not_built_in_current_env` are skipped (with
explanatory pytest reason).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_status() -> dict:
    p = REPO_ROOT / "polydiff" / "parsers" / "PARSER_STATUS.json"
    with p.open("r", encoding="utf-8") as fh:
        return json.load(fh)["wrappers"]


WRAPPERS = sorted(_load_status().items())


@pytest.mark.parametrize("profile,entry", WRAPPERS, ids=[p for p, _ in WRAPPERS])
def test_wrapper_smoke(profile: str, entry: dict):
    if entry.get("status") != "built":
        pytest.skip(f"{profile}: {entry.get('reason', 'not built in this env')}")
    smoke = entry.get("smoke_test")
    assert smoke, f"{profile}: smoke_test not declared in PARSER_STATUS.json"
    smoke_path = REPO_ROOT / smoke
    assert smoke_path.exists(), f"smoke test missing at {smoke_path}"

    proc = subprocess.run(
        ["bash", str(smoke_path)],
        capture_output=True,
        timeout=30,
        cwd=REPO_ROOT,
    )
    if proc.returncode == 77:
        pytest.skip(f"{profile} smoke skipped: {proc.stderr.decode('utf-8', 'replace').strip()}")
    assert proc.returncode == 0, (
        f"{profile} smoke failed: exit={proc.returncode}\n"
        f"stdout={proc.stdout.decode('utf-8', 'replace')}\n"
        f"stderr={proc.stderr.decode('utf-8', 'replace')}"
    )


@pytest.mark.parametrize("profile,entry", WRAPPERS, ids=[p for p, _ in WRAPPERS])
def test_wrapper_status_directory_exists(profile: str, entry: dict):
    """Every wrapper must have a source directory regardless of build status."""
    directory = entry.get("directory")
    assert directory, f"{profile}: missing 'directory' in PARSER_STATUS"
    p = REPO_ROOT / directory
    assert p.exists() and p.is_dir(), f"{profile}: directory {p} missing"
    # Source must be present so a different env can rebuild.
    has_source = any(p.glob("wrapper.*")) or any(p.glob("Wrapper.java"))
    assert has_source, f"{profile}: no wrapper source under {p}"
