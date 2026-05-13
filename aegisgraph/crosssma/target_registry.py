"""Commit-pinned manifest of SMA targets for CrossSMA queries.

Reads `aegisgraph/crosssma/registry/targets.yaml`, validates that the
verified targets (signal-android, element-x-android) agree with
`aegisgraph.constants.TARGETS`, and returns a read-only mapping of
target_id -> frozen `Target` objects.

`load_registry()` returns a fresh mapping each call so a caller's
accidental mutation cannot leak across tests.

Immutability surface:

  * `Target` is a frozen dataclass: attribute assignment raises.
  * `Target.path_classes` and `Target.dependency_snapshot` are tuples.
  * The returned `Mapping[str, Target]` is a fresh dict instance each
    call. Tests assert this.

Target.verified is `True` only when the commit pin has been visually
confirmed against the upstream repository. Verified=False targets
ship with `commit` set to a `TODO-` placeholder; downstream queries
SHOULD render their cells as dependency_absent unless the dependency
snapshot itself matches.

Wave 9C additive fields (ADR-0010 compatible):

  * ``deferred_to`` -- Optional milestone id (e.g. ``"M22.1"``) for
    placeholder commit pins, naming when the pin will resolve.
    ``None`` for verified entries and for unverified entries that
    carry a real SHA but are pending review. Required for any
    ``TODO-*-COMMIT`` placeholder; the guard tests under
    ``tests/crosssma/test_targets_yaml_no_orphan_todo.py`` enforce
    that contract on the raw YAML so loader bugs cannot hide it.
  * ``deferral_note`` -- Optional human-readable rationale.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from aegisgraph.constants import TARGETS as GLOBAL_TARGETS
from aegisgraph.io import repo_root


REGISTRY_REL_PATH = "aegisgraph/crosssma/registry/targets.yaml"


@dataclass(frozen=True)
class Target:
    """Frozen target record. Mutation raises AttributeError.

    The ``deferred_to`` / ``deferral_note`` fields are additive
    (Wave 9C, ADR-0010 compatible). They default to ``None`` so
    pre-9C callers that constructed Target() positionally without
    them continue to work.
    """

    target_id: str
    name: str
    repo_url: str
    commit: str
    verified: bool
    path_classes: tuple[str, ...]
    dependency_snapshot: tuple[str, ...]
    deferred_to: str | None = None
    deferral_note: str | None = None


class RegistryConsistencyError(ValueError):
    """Raised when targets.yaml disagrees with `aegisgraph.constants.TARGETS`
    for a verified target. The fix is to update both files in lockstep."""


def _registry_path(root: Path | None = None) -> Path:
    base = root or repo_root()
    return base / REGISTRY_REL_PATH


def _load_yaml(root: Path | None = None) -> dict[str, Any]:
    path = _registry_path(root)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(
            f"targets.yaml at {path} did not parse as a mapping"
        )
    return data


def _entry_to_target(target_id: str, entry: dict[str, Any]) -> Target:
    name = str(entry.get("name", target_id))
    repo_url = str(entry["repo_url"])
    commit = str(entry["commit"])
    verified = bool(entry.get("verified", False))
    path_classes = tuple(entry.get("path_classes") or ())
    dependency_snapshot = tuple(entry.get("dependency_snapshot") or ())
    # Additive (Wave 9C, ADR-0010): optional deferral metadata for
    # placeholder commit pins. Both fields are normalized to strings
    # when present, or left as None for verified / unannotated entries.
    deferred_to_raw = entry.get("deferred_to")
    deferred_to = str(deferred_to_raw) if deferred_to_raw else None
    deferral_note_raw = entry.get("deferral_note")
    deferral_note = str(deferral_note_raw) if deferral_note_raw else None
    return Target(
        target_id=target_id,
        name=name,
        repo_url=repo_url,
        commit=commit,
        verified=verified,
        path_classes=path_classes,
        dependency_snapshot=dependency_snapshot,
        deferred_to=deferred_to,
        deferral_note=deferral_note,
    )


# Mapping from CrossSMA target_id -> global TARGETS key. We don't add
# wire-android / telegram-android to the global; only the verified
# pair maps over.
_GLOBAL_KEY_MAP = {
    "signal-android": "signal",
    "element-x-android": "element-x",
}


def _check_consistency_against_global(targets: dict[str, Target]) -> None:
    for crosssma_id, global_key in _GLOBAL_KEY_MAP.items():
        if crosssma_id not in targets:
            continue
        local = targets[crosssma_id]
        if not local.verified:
            continue
        global_entry = GLOBAL_TARGETS.get(global_key)
        if global_entry is None:
            continue
        if global_entry["commit"] != local.commit:
            raise RegistryConsistencyError(
                f"CrossSMA registry commit pin for {crosssma_id!r} "
                f"({local.commit!r}) disagrees with "
                f"aegisgraph.constants.TARGETS[{global_key!r}].commit "
                f"({global_entry['commit']!r}). Update both in one PR."
            )


def load_registry(root: Path | None = None) -> dict[str, Target]:
    """Load the 4-target manifest. Returns a fresh dict each call so
    caller mutation cannot poison subsequent loads.

    Raises `RegistryConsistencyError` if a verified target's commit
    pin disagrees with `aegisgraph.constants.TARGETS`.
    """
    data = _load_yaml(root)
    targets_yaml = data.get("targets", {})
    if not isinstance(targets_yaml, dict):
        raise ValueError("targets.yaml: 'targets' must be a mapping")
    targets: dict[str, Target] = {}
    for target_id, entry in targets_yaml.items():
        if not isinstance(entry, dict):
            raise ValueError(f"targets.yaml: entry for {target_id!r} is not a mapping")
        targets[str(target_id)] = _entry_to_target(str(target_id), entry)
    _check_consistency_against_global(targets)
    return targets


__all__ = [
    "Target",
    "RegistryConsistencyError",
    "load_registry",
    "REGISTRY_REL_PATH",
]
