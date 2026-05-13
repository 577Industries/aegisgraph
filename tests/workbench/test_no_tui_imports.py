"""Negative test: no TUI surfaces under aegisgraph/workbench/.

Forbidden: curses, textual, rich.live, prompt_toolkit. Static `rich`
output (e.g. `rich.table.Table` rendered once) is allowed; the live /
interactive surfaces are what we ban because they would couple the
workbench to a terminal session manager that doesn't compose with
the rest of the AegisGraph pipeline.
"""

from __future__ import annotations

import re
from pathlib import Path


_FORBIDDEN_PATTERNS = (
    r"\bimport\s+curses\b",
    r"\bfrom\s+curses\b",
    r"\bimport\s+textual\b",
    r"\bfrom\s+textual\b",
    r"\bfrom\s+rich\.live\b",
    r"\bimport\s+prompt_toolkit\b",
    r"\bfrom\s+prompt_toolkit\b",
    r"\bimport\s+npyscreen\b",
    r"\bfrom\s+npyscreen\b",
    r"\bimport\s+urwid\b",
    r"\bfrom\s+urwid\b",
    r"\bimport\s+blessed\b",
    r"\bfrom\s+blessed\b",
)


def _workbench_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "aegisgraph" / "workbench"


def test_workbench_has_no_tui_imports() -> None:
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
