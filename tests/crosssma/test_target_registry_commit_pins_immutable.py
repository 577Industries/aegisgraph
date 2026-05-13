"""Target registry immutability test.

Per ADR principles + Phase II §15 R-ENG-4: commit pins in the
CrossSMA target registry are part of the reproducibility contract.
Once `load_registry()` returns, callers MUST NOT be able to mutate
the result and silently change which commit a downstream query
runs against. Mutation attempts raise.

This is structural defense against a class of bugs where a CrossSMA
query mutates a target_dict in-place during iteration and the next
test (or next run of the same harness) sees the wrong commit pin.
"""

from __future__ import annotations

import pytest

from aegisgraph.crosssma.target_registry import (
    Target,
    load_registry,
)


def test_target_registry_returns_frozen_targets() -> None:
    """Each Target instance is frozen — direct attribute writes raise."""
    registry = load_registry()
    target = registry.get("signal-android")
    assert target is not None
    with pytest.raises((AttributeError, TypeError, Exception)):
        # frozen dataclass should refuse this
        target.commit = "deadbeef"  # type: ignore[misc]


def test_target_registry_returns_independent_snapshots() -> None:
    """Two loads of the registry return independent objects; mutating
    one cannot leak into another. (Defends against module-level cache
    aliasing.)"""
    reg_a = load_registry()
    reg_b = load_registry()
    # Even if implementations cache internally, the returned mapping must
    # not be the SAME mutable object so that a caller's mutation can't
    # poison the next call.
    assert reg_a is not reg_b or _is_read_only_mapping(reg_a)


def test_dependency_snapshot_is_tuple_or_frozen() -> None:
    """A target's dependency_snapshot must be an immutable sequence so
    cross-target queries cannot mutate it during iteration."""
    registry = load_registry()
    target = registry.get("signal-android")
    assert target is not None
    deps = target.dependency_snapshot
    # Must reject .append (i.e. it's a tuple, frozenset, or read-only)
    with pytest.raises((AttributeError, TypeError, Exception)):
        deps.append("malicious-dep")  # type: ignore[attr-defined]


def test_path_classes_is_tuple_not_list() -> None:
    registry = load_registry()
    target = registry.get("signal-android")
    assert target is not None
    assert isinstance(target.path_classes, tuple), (
        "path_classes should be a tuple for immutability"
    )


def _is_read_only_mapping(obj: object) -> bool:
    try:
        obj["__probe__"] = "x"  # type: ignore[index]
        return False
    except (TypeError, AttributeError):
        return True


def test_target_registry_keys_match_target_id() -> None:
    """Registry keys must equal target.target_id so lookups via either
    are consistent."""
    registry = load_registry()
    for key, target in registry.items():
        assert key == target.target_id, (
            f"registry key {key!r} != target.target_id {target.target_id!r}"
        )
