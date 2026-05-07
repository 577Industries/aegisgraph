"""Pointer file — actual traceability matrix tests are in
``tests/test_traceability_matrix.py``.

See ``test_sanitize_check.py`` for the rationale (we don't re-export
tests because pytest would then collect them twice).
"""
from __future__ import annotations

from pathlib import Path


def test_traceability_canonical_suite_is_test_traceability_matrix() -> None:
    canonical = Path(__file__).parent / "test_traceability_matrix.py"
    assert canonical.exists()
