#!/usr/bin/env python3
"""SPEC-mandated entry point for the URL corpus.

The real implementation lives in `smabench.ring1.url_corpus` (Python
identifier rules forbid dashes in module names). This shim exists so
`smabench/ring1/url-corpus/generate.py` works as a standalone CLI
matching the SPEC §7.1 layout.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_repo_on_path() -> None:
    here = Path(__file__).resolve()
    # .worktree/smabench/smabench/ring1/url-corpus/generate.py
    repo_root = here.parents[3]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))


if __name__ == "__main__":
    _ensure_repo_on_path()
    from smabench.ring1 import url_corpus

    raise SystemExit(url_corpus.main(sys.argv[1:]))
