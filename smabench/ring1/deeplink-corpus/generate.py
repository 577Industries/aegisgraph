#!/usr/bin/env python3
"""SPEC-mandated entry point for the deeplink corpus.

Real implementation: `smabench.ring1.deeplink_corpus`.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_repo_on_path() -> None:
    here = Path(__file__).resolve()
    repo_root = here.parents[3]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))


if __name__ == "__main__":
    _ensure_repo_on_path()
    from smabench.ring1 import deeplink_corpus

    raise SystemExit(deeplink_corpus.main(sys.argv[1:]))
