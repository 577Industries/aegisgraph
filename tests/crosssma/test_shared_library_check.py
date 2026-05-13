"""shared_library_check query test.

Asks "does target X depend on libwebp@vulnerable?" — answering by
inspecting the target's dependency_snapshot in the registry. This
is purely structural (no source pulls, no network)."""

from __future__ import annotations

from aegisgraph.crosssma.queries.shared_library_check import (
    check_shared_library,
)
from aegisgraph.crosssma.target_registry import Target


def _mock_target_with(deps: tuple[str, ...]) -> Target:
    return Target(
        target_id="mock-target",
        name="Mock Target",
        repo_url="https://example.invalid/mock",
        commit="0000000",
        verified=False,
        path_classes=tuple(),
        dependency_snapshot=deps,
    )


def test_target_with_libwebp_dep_detected() -> None:
    target = _mock_target_with(("libwebp@1.3.1", "okhttp@4.12.0"))
    result = check_shared_library(target, library="libwebp")
    assert result.present is True
    assert result.matched_dep == "libwebp@1.3.1"


def test_target_without_libwebp_dep_returns_absent() -> None:
    target = _mock_target_with(("okhttp@4.12.0", "glide@4.16.0"))
    result = check_shared_library(target, library="libwebp")
    assert result.present is False
    assert result.matched_dep is None


def test_library_match_is_prefix_aware() -> None:
    """`libwebp` should match `libwebp@1.3.1`, `libwebp@2.0.0`, etc.
    It must NOT match `libwebpd` (a false-positive prefix)."""
    t1 = _mock_target_with(("libwebp@1.3.1",))
    t2 = _mock_target_with(("libwebpd@1.0.0",))
    assert check_shared_library(t1, library="libwebp").present is True
    assert check_shared_library(t2, library="libwebp").present is False


def test_signal_registry_dependency_check_runs() -> None:
    """Smoke: the real registry target answers the query without error.
    We don't assert presence/absence of any specific dep here — that's
    a data-snapshot concern."""
    from aegisgraph.crosssma.target_registry import load_registry

    target = load_registry()["signal-android"]
    result = check_shared_library(target, library="libwebp")
    assert isinstance(result.present, bool)
