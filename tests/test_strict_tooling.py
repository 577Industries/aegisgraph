"""Pointer file — actual strict-tooling tests are in
``tests/test_validator_strict_tooling.py``.

See ``test_sanitize_check.py`` for the rationale (we don't re-export
tests because pytest would then collect them twice).
"""
from __future__ import annotations

from pathlib import Path


def test_strict_tooling_canonical_suite_is_test_validator_strict_tooling() -> None:
    canonical = Path(__file__).parent / "test_validator_strict_tooling.py"
    assert canonical.exists()
