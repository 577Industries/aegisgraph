from __future__ import annotations

from dataclasses import dataclass

from .constants import CLAIM_STATE_ORDER, CLAIM_STATES


V02_V03_CLAIM_STATE_MAP = {
    "candidate": "observed",
    "static_supported": "anchored",
    "priority_validation": "validation_tasked",
    "harness_covered": "reviewed",
    "synthetic_dynamic_observed": "reviewed",
    "authorized_dynamic_observed": "reviewed",
    "externally_correlated": "reviewed",
    "defensive_recommendation": "accepted",
    "vulnerability_claim": "limited",
}

ALIASES = {
    "validation-tasked": "validation_tasked",
    **V02_V03_CLAIM_STATE_MAP,
}


@dataclass(frozen=True)
class ClaimStateTransition:
    previous: str
    next: str
    valid: bool
    reason: str


def canonical_claim_state(state: str) -> str:
    normalized = ALIASES.get(state, state)
    if normalized not in CLAIM_STATES:
        allowed = ", ".join(CLAIM_STATES)
        raise ValueError(f"unknown claim state {state!r}; expected one of {allowed}")
    return normalized


def migrate_record_claim_state(record: dict) -> dict:
    migrated = dict(record)
    if "claim_state" in migrated:
        migrated["claim_state"] = canonical_claim_state(migrated["claim_state"])
    return migrated


def transition_allowed(previous: str, next_state: str) -> ClaimStateTransition:
    prev = canonical_claim_state(previous)
    nxt = canonical_claim_state(next_state)
    if prev == "retired":
        return ClaimStateTransition(prev, nxt, nxt == "retired", "retired claims cannot be promoted")
    valid = CLAIM_STATE_ORDER[nxt] >= CLAIM_STATE_ORDER[prev] or nxt in {"limited", "retired"}
    reason = "monotonic transition" if valid else "claim state cannot move backward without retirement"
    return ClaimStateTransition(prev, nxt, valid, reason)
