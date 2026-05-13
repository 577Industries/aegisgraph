"""Negative test: the workbench package must never import a web framework.

Web frameworks introduce an HTTP attack surface and an out-of-band
state machine (sessions, cookies, etc.) that contradict the
strictly-CLI-only Wave 8B charter. This test scans every .py under
aegisgraph/workbench/ for the forbidden import tokens.
"""

from __future__ import annotations

import re
from pathlib import Path


_FORBIDDEN_PATTERNS = (
    r"\bimport\s+flask\b",
    r"\bfrom\s+flask\b",
    r"\bimport\s+fastapi\b",
    r"\bfrom\s+fastapi\b",
    r"\baiohttp\.web\b",
    r"\bfrom\s+aiohttp\s+import\s+web\b",
    r"\bimport\s+starlette\b",
    r"\bfrom\s+starlette\b",
    r"\bimport\s+sanic\b",
    r"\bfrom\s+sanic\b",
    r"\bimport\s+tornado\b",
    r"\bfrom\s+tornado\b",
    r"\bimport\s+bottle\b",
    r"\bfrom\s+bottle\b",
)


def _workbench_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "aegisgraph" / "workbench"


def test_workbench_has_no_web_imports() -> None:
    """No file under aegisgraph/workbench/ imports a web framework."""
    failures: list[str] = []
    for path in sorted(_workbench_dir().rglob("*.py")):
        if path.name.startswith("test_"):
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in _FORBIDDEN_PATTERNS:
            match = re.search(pattern, text)
            if match:
                failures.append(f"{path}: forbidden pattern /{pattern}/ at offset {match.start()}")
    assert not failures, "\n".join(failures)
