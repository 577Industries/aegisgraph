"""PolyDiff facade.

Preserves the historical `aegisgraph.polydiff` import surface so that
`aegisgraph/cli.py:cmd_polydiff` (cli.py:80 — calls
`polydiff.run_regression(_root())`), the test suite, and downstream
callers continue to work without modification.

T-M2.3 (PolyDiff URL family refactor) splits the original ~490-line
`aegisgraph/polydiff.py` into a subpackage with this shape:

  aegisgraph/polydiff/
  ├── __init__.py              # this file — facade + module-level re-exports
  ├── core/
  │   ├── factvector.py        # generic subprocess wrapper dispatch
  │   ├── triage.py            # Disagreement + detect_disagreements
  │   └── reachability.py      # (placeholder for future)
  └── families/
      └── url/
          ├── profiles.py      # URL wrapper profiles + fact_vectors_for
          └── regression.py    # URL regression corpus + run_regression body

The facade keeps `write_json`, `fact_vectors_for`, and
`detect_disagreements` as module-level attributes so that the historical
monkeypatch contract holds — tests do `monkeypatch.setattr(aegisgraph.polydiff,
"write_json", fake)` and expect the patch to flow through `run_regression`.
This is achieved by `run_regression()` closing over the module-level
names and injecting them into the URL family's regression
implementation.

Pure refactor — no behavior change. The regression report.json and
evidence.json bytes are SHA-256-stable across this commit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# Module-level patchable attributes — preserve the historical
# monkeypatch contract (tests setattr these on the facade module).
from aegisgraph.constants import STATIC_GENERATED_AT
from aegisgraph.io import write_json

from .core.factvector import _crash_envelope, run_wrapper
from .core.triage import Disagreement, detect_disagreements
from .families.url.profiles import (
    PARSER_STATUS_FILENAME,
    _wrapper_command,
    fact_vectors_for,
    load_parser_status,
)
from .families.url.regression import (
    _finding_record,
    _load_cases,
    _matches_expected,
    _normalize_record_id,
    run_regression as _url_run_regression,
)


def run_regression(root: Path) -> dict[str, Any]:
    """End-to-end regression run (URL family today).

    Thin facade delegating to `aegisgraph.polydiff.families.url.regression.run_regression`
    while injecting the facade's module-level `write_json`,
    `fact_vectors_for`, and `detect_disagreements` so that test
    monkeypatching of those names (on `aegisgraph.polydiff`) takes
    effect for the run.
    """
    return _url_run_regression(
        root,
        write_json=write_json,
        fact_vectors_for=fact_vectors_for,
        detect_disagreements=detect_disagreements,
    )


__all__ = [
    "Disagreement",
    "detect_disagreements",
    "fact_vectors_for",
    "load_parser_status",
    "run_regression",
    "run_wrapper",
    "write_json",
    "STATIC_GENERATED_AT",
    "PARSER_STATUS_FILENAME",
]
