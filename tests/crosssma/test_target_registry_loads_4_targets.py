"""Target registry contents test.

CrossSMA v0 ships a 4-target registry: signal-android, element-x-android,
wire-android (stub), telegram-android (stub). This test verifies the
YAML at aegisgraph/crosssma/registry/targets.yaml decodes to those 4
target ids and that the verified targets (signal, element-x) match
the commit pins from aegisgraph.constants.TARGETS (which remain
unchanged per the additive-extension contract).
"""

from __future__ import annotations

from aegisgraph.constants import TARGETS
from aegisgraph.crosssma.target_registry import load_registry


def test_registry_contains_four_targets() -> None:
    registry = load_registry()
    assert set(registry.keys()) == {
        "signal-android",
        "element-x-android",
        "wire-android",
        "telegram-android",
    }


def test_signal_commit_pin_matches_global_constants() -> None:
    """The CrossSMA registry MUST NOT contradict aegisgraph.constants.TARGETS
    for the two existing targets. If a future PR bumps the Signal commit,
    update both in one PR."""
    registry = load_registry()
    assert registry["signal-android"].commit == TARGETS["signal"]["commit"]
    assert registry["element-x-android"].commit == TARGETS["element-x"]["commit"]


def test_constants_targets_not_mutated_by_crosssma() -> None:
    """Loading the CrossSMA registry must NOT add wire-android /
    telegram-android into aegisgraph.constants.TARGETS. The extension
    is local to CrossSMA per the additive-extension contract."""
    # Touch the registry first; it must not mutate the global.
    load_registry()
    assert set(TARGETS.keys()) == {"signal", "element-x"}, (
        "aegisgraph.constants.TARGETS was mutated by CrossSMA registry "
        "load; the extension must remain CrossSMA-local"
    )


def test_signal_target_carries_8_path_classes() -> None:
    """The 8 path classes from aegisgraph.constants.PATH_CLASSES should
    be reflected as a per-target attribute. (This avoids hardcoding
    them into queries.)"""
    registry = load_registry()
    target = registry["signal-android"]
    assert len(target.path_classes) == 8


def test_wire_and_telegram_are_stub_pins() -> None:
    """Wire + Telegram ship as stubs in v0 — commit is allowed to be
    a placeholder (documented in registry README). The registry must
    mark them as `verified=False` so consumers know not to fan-out
    real commit-bound work yet."""
    registry = load_registry()
    assert registry["wire-android"].verified is False
    assert registry["telegram-android"].verified is False


def test_signal_and_elementx_are_verified_pins() -> None:
    registry = load_registry()
    assert registry["signal-android"].verified is True
    assert registry["element-x-android"].verified is True


def test_target_carries_repo_url() -> None:
    registry = load_registry()
    sig = registry["signal-android"]
    assert sig.repo_url.startswith("https://"), (
        f"signal-android repo_url must be https URL, got {sig.repo_url!r}"
    )
