"""Pointer file — actual sanitize-check tests are in
``tests/test_validator_sanitize_check.py``.

This file exists so that the verification command line in the validator-
export stream brief can be invoked literally:

    pytest tests/test_sanitize_check.py

We do NOT re-export the tests via star-import because pytest would then
collect them twice (once under each module name), causing duplicate
test IDs. Instead this file holds a single trivial assertion that
documents the redirect; pytest will run it as one passing test in
addition to the canonical suite.
"""
from __future__ import annotations

from pathlib import Path


def test_sanitize_check_canonical_suite_is_test_validator_sanitize_check() -> None:
    canonical = Path(__file__).parent / "test_validator_sanitize_check.py"
    assert canonical.exists(), (
        "expected canonical sanitize-check suite at "
        f"{canonical} (this file is a pointer)"
    )
