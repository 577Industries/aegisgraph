"""analogous_code_check: structural pattern -> target plausibility.

v0 implementation is a path-class heuristic: each pattern family
maps to one or more path classes. A target plausibly hosts a pattern
of family F iff its path_classes contains any of the path classes F
maps to. AST-level matching arrives in a later milestone.

The heuristic table is conservative: only well-known mappings appear.
Unknown families return `matches=False`, NOT True -- we err toward
candidate_path or dependency_absent rather than over-claiming.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegisgraph.crosssma.pattern_extractor import PatternFingerprint
from aegisgraph.crosssma.target_registry import Target


# Family -> path classes that plausibly host the pattern. Conservative
# coverage: extend as new families are validated.
_FAMILY_TO_PATH_CLASSES: dict[str, tuple[str, ...]] = {
    "url": ("link_preview", "deeplink", "inbound_message"),
    "image": ("media_decode",),
    "video": ("media_decode",),
    "audio": ("media_decode",),
    "qr": ("qr_device_link",),
    "deeplink": ("deeplink",),
    "sync": ("sync_state",),
    "crypto": ("crypto_key_lifecycle",),
    "native": ("native_boundary",),
    "pq_protocol": ("crypto_key_lifecycle", "sync_state"),
    "pq_protocol_migration": ("crypto_key_lifecycle", "sync_state"),
}


@dataclass(frozen=True)
class AnalogousCodeResult:
    target_id: str
    family: str
    matches: bool
    matched_path_classes: tuple[str, ...]


def check_analogous_code(
    target: Target, fingerprint: PatternFingerprint
) -> AnalogousCodeResult:
    """Conservative path-class heuristic for v0. Returns matches=True
    iff the target hosts at least one path class plausibly relevant
    to the fingerprint's family."""
    family = fingerprint.family.lower()
    relevant = _FAMILY_TO_PATH_CLASSES.get(family, ())
    matched = tuple(pc for pc in target.path_classes if pc in relevant)
    return AnalogousCodeResult(
        target_id=target.target_id,
        family=family,
        matches=bool(matched),
        matched_path_classes=matched,
    )


__all__ = ["AnalogousCodeResult", "check_analogous_code"]
