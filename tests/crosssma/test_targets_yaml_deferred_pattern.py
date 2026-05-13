"""Pattern test for the deferred_to / verified-commit dichotomy.

For each target in `aegisgraph/crosssma/registry/targets.yaml`:

  * If `verified: true`, `commit` MUST look like a real SHA prefix
    (hex, length >= 7, not a TODO placeholder).
  * If `verified: false`, EITHER `commit` is a real-looking SHA
    (an unverified-but-known pin) OR `deferred_to` is present
    naming the milestone that resolves the pin.

This guards against three drift patterns:

  1. A verified pin that was accidentally replaced by a placeholder
  2. An unverified pin that lost its `deferred_to` companion
  3. An unverified pin that is BOTH a TODO stub AND has no deferral

Also asserts that `deferred_to`, when present, conforms to a
milestone-id shape (M<digits>[.<digits>...]). M22.1 is the canonical
Phase II authorization-workflow milestone for additional SMA targets.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml


REGISTRY_REL_PATH = "aegisgraph/crosssma/registry/targets.yaml"

# A "real-looking" commit SHA: 7+ lowercase hex characters. The repo's
# verified pins use short SHAs (e.g. "1043851", "91d265e6"); permit
# both short and full-length hex.
_SHA_PATTERN = re.compile(r"^[0-9a-f]{7,40}$")

# Milestone id shape: 'M' + digits, optionally with .digits parts.
# Examples: M22, M22.1, M14, M9.1.
_MILESTONE_PATTERN = re.compile(r"^M\d+(?:\.\d+)*$")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_raw_targets() -> dict:
    path = _repo_root() / REGISTRY_REL_PATH
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    targets = data.get("targets", {})
    assert isinstance(targets, dict)
    return targets


def _looks_like_sha(commit: str) -> bool:
    return isinstance(commit, str) and bool(_SHA_PATTERN.match(commit))


def test_verified_targets_have_real_sha() -> None:
    """Every verified target MUST have a commit that looks like a SHA."""
    targets = _load_raw_targets()
    bad = []
    for target_id, entry in targets.items():
        if not isinstance(entry, dict):
            continue
        if bool(entry.get("verified", False)):
            commit = entry.get("commit", "")
            if not _looks_like_sha(commit):
                bad.append(
                    f"{target_id}: verified=true but commit={commit!r} "
                    f"is not a real-looking SHA"
                )
    assert not bad, (
        f"Verified targets with non-SHA commits: {bad}"
    )


def test_unverified_targets_have_sha_or_deferral() -> None:
    """Every unverified target MUST either have a real-looking SHA
    pin (an honest unverified pin -- e.g. pending review) OR a
    `deferred_to` field documenting the milestone that will resolve."""
    targets = _load_raw_targets()
    violations = []
    for target_id, entry in targets.items():
        if not isinstance(entry, dict):
            continue
        if bool(entry.get("verified", False)):
            continue
        commit = entry.get("commit", "")
        has_sha = _looks_like_sha(commit)
        has_deferred = bool(entry.get("deferred_to"))
        if not (has_sha or has_deferred):
            violations.append(
                f"{target_id}: verified=false, commit={commit!r}, "
                f"deferred_to={entry.get('deferred_to')!r} -- "
                f"need either real SHA OR deferred_to"
            )
    assert not violations, (
        "Unverified targets must carry a real SHA or a deferral: "
        f"{violations}"
    )


def test_deferred_to_uses_milestone_shape() -> None:
    """`deferred_to` values must look like a milestone id (M\\d+...)."""
    targets = _load_raw_targets()
    bad = []
    for target_id, entry in targets.items():
        if not isinstance(entry, dict):
            continue
        deferred_to = entry.get("deferred_to")
        if deferred_to is None:
            continue
        if not isinstance(deferred_to, str) or not _MILESTONE_PATTERN.match(deferred_to):
            bad.append(
                f"{target_id}: deferred_to={deferred_to!r} "
                f"does not match milestone shape M<digits>[.<digits>...]"
            )
    assert not bad, f"Malformed deferred_to values: {bad}"


def test_wire_and_telegram_resolved() -> None:
    """Wave 9C specific: wire-android and telegram-android entries must
    either be verified-pinned OR carry a deferred_to. The pre-9C orphan
    TODO state is no longer acceptable."""
    targets = _load_raw_targets()
    for target_id in ("wire-android", "telegram-android"):
        entry = targets.get(target_id)
        assert isinstance(entry, dict), (
            f"missing or malformed registry entry for {target_id}"
        )
        commit = entry.get("commit", "")
        verified = bool(entry.get("verified", False))
        deferred_to = entry.get("deferred_to")
        if verified:
            assert _looks_like_sha(commit), (
                f"{target_id}: verified=true requires real SHA, got {commit!r}"
            )
        else:
            assert _looks_like_sha(commit) or deferred_to, (
                f"{target_id}: must be verified-pinned OR carry deferred_to; "
                f"got commit={commit!r}, deferred_to={deferred_to!r}"
            )
