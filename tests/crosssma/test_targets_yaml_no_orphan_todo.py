"""Guard against orphan TODO commit stubs in the CrossSMA registry.

Wave 9C resolution rule: a target entry in
`aegisgraph/crosssma/registry/targets.yaml` may carry a placeholder
commit pin of the form ``TODO-...-COMMIT`` ONLY IF the entry also
carries a companion ``deferred_to`` field documenting the milestone
that will resolve the pin. An "orphan TODO" -- placeholder commit
without a deferred_to -- is the drift state we are guarding against.

Per ADR-0010 additive extension policy: ``deferred_to`` is a new
optional field. Verified targets do not require it; only entries
with ``verified: false`` that retain a TODO stub need it.

This test loads the YAML directly (not via the loader) so the guard
also catches malformed entries that the loader might otherwise drop.
"""

from __future__ import annotations

from pathlib import Path

import yaml


REGISTRY_REL_PATH = "aegisgraph/crosssma/registry/targets.yaml"


def _repo_root() -> Path:
    # tests/crosssma/<this>.py -> tests/crosssma -> tests -> repo
    return Path(__file__).resolve().parents[2]


def _load_raw_targets() -> dict:
    path = _repo_root() / REGISTRY_REL_PATH
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert isinstance(data, dict), (
        f"{REGISTRY_REL_PATH} did not parse as a mapping"
    )
    targets = data.get("targets", {})
    assert isinstance(targets, dict), (
        f"{REGISTRY_REL_PATH}: 'targets' must be a mapping"
    )
    return targets


def _is_todo_stub(commit: str) -> bool:
    """A placeholder commit pin: starts with 'TODO-' and ends '-COMMIT'."""
    if not isinstance(commit, str):
        return False
    return commit.startswith("TODO-") and commit.endswith("-COMMIT")


def test_no_target_has_todo_commit_without_deferred_to() -> None:
    """A TODO-*-COMMIT placeholder MUST be accompanied by a
    `deferred_to` field that names the milestone resolving the pin."""
    targets = _load_raw_targets()
    orphans = []
    for target_id, entry in targets.items():
        if not isinstance(entry, dict):
            continue
        commit = entry.get("commit", "")
        if _is_todo_stub(commit):
            deferred_to = entry.get("deferred_to")
            if not deferred_to:
                orphans.append(
                    f"{target_id}: commit={commit!r} has no `deferred_to`"
                )
    assert not orphans, (
        "Orphan TODO commit stubs found in targets.yaml -- "
        "every TODO-*-COMMIT placeholder must carry a companion "
        "`deferred_to: <milestone>` field per ADR-0010 additive policy. "
        f"Orphans: {orphans}"
    )


def test_todo_stub_target_must_be_verified_false() -> None:
    """A target with a TODO-*-COMMIT placeholder must be marked
    `verified: false`. A TODO pin cannot claim verified=true."""
    targets = _load_raw_targets()
    bad = []
    for target_id, entry in targets.items():
        if not isinstance(entry, dict):
            continue
        commit = entry.get("commit", "")
        if _is_todo_stub(commit):
            if bool(entry.get("verified", False)):
                bad.append(
                    f"{target_id}: TODO pin {commit!r} cannot be verified=true"
                )
    assert not bad, (
        "TODO commit stubs marked verified=true; this contradicts the "
        f"placeholder semantics: {bad}"
    )


def test_deferred_to_only_present_when_unverified() -> None:
    """`deferred_to` is only meaningful for an unverified entry.
    A verified target should not carry a deferred_to field; if a pin
    becomes verified, the deferred_to must be removed."""
    targets = _load_raw_targets()
    bad = []
    for target_id, entry in targets.items():
        if not isinstance(entry, dict):
            continue
        if bool(entry.get("verified", False)) and entry.get("deferred_to"):
            bad.append(
                f"{target_id}: verified=true but carries "
                f"deferred_to={entry.get('deferred_to')!r}"
            )
    assert not bad, (
        "deferred_to should be removed when a target becomes verified: "
        f"{bad}"
    )
