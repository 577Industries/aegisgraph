#!/usr/bin/env python3
"""SPEC-mandated entry point for the media corpus.

Real implementation: `smabench.ring1.media_corpus`. Emits VALID image
samples only (no crash inputs); see the module docstring for rationale.
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
    from smabench.ring1 import media_corpus

    raise SystemExit(media_corpus.main(sys.argv[1:]))
