"""PolyDiff core: family-agnostic primitives.

- `factvector` — generic subprocess wrapper dispatch + crash envelope
- `triage` — generic `Disagreement` dataclass + `detect_disagreements`
- `reachability` — placeholder for cross-family reachability mapping
"""

from __future__ import annotations

from .factvector import run_wrapper, _crash_envelope, SUBPROCESS_TIMEOUT_S
from .triage import Disagreement, detect_disagreements


__all__ = [
    "Disagreement",
    "detect_disagreements",
    "run_wrapper",
    "_crash_envelope",
    "SUBPROCESS_TIMEOUT_S",
]
