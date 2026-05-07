from __future__ import annotations

from copy import deepcopy
from typing import Any

from .constants import STATIC_GENERATED_AT
from .hashchain import attach_hash_chain
from .io import sha256_text
from .safety import apply_safety_flags, blocking_flags, scan_record


class UnsafeFinalizationError(RuntimeError):
    """Raised when finalize_record() is asked to seal a record that contains
    blocking safety flags AND is being prepared for public release.

    Once a record carries `release_classification="public_sanitized"` (or any
    non-private classification) the safety scanner's blocking flags are NOT
    advisory: hashing them into the chain would let an unsafe record reach a
    public export manifest. The integration contract is fail-closed: surface
    the violation here, before the hash-chain step, so the caller has a
    chance to either redact the offending field or downgrade the
    classification back to private.

    See docs/decision-log/0010-schema-additive-only.md for why we don't try
    to silently strip fields, and 0011-public-export-human-gate.md for the
    public-export specific gating.
    """

    def __init__(self, record_id: str, flag_rules: list[str]):
        self.record_id = record_id
        self.flag_rules = flag_rules
        super().__init__(
            f"record {record_id!r} carries blocking safety flags "
            f"({', '.join(flag_rules)}) and cannot be finalized for public release"
        )


# Records with one of these release_classification values are subject to
# the public-release safety gate inside finalize_record. Anything not on
# this list (including the historical default of unset) defaults to private,
# in which case scan results are recorded but do not raise.
_PUBLIC_RELEASE_CLASSIFICATIONS = frozenset(
    {
        "public_sanitized",
        "public_release",
    }
)


def evidence_ref(ref_id: str, tool: str, command: str, content: str, version: str = "phase0") -> dict[str, str]:
    return {
        "id": ref_id,
        "tool": tool,
        "version": version,
        "command": command,
        "output_hash": sha256_text(content),
    }


def provenance(source: str) -> dict[str, Any]:
    return {
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "source": source,
        "private_by_default": True,
    }


def finalize_record(record: dict[str, Any], previous_hash: str | None = None) -> dict[str, Any]:
    """Apply safety flags, hash, chain. Public-classified records raise on blocks.

    Order of operations is load-bearing:
      1. deepcopy + default missing arrays so the schema-required fields
         exist before any scan touches them.
      2. apply_safety_flags() runs scan_record() and attaches flags to the
         record dict; the flags become part of the canonicalized payload
         that hashchain.attach_hash_chain hashes. This is what the SPEC
         calls 'safety-into-hash-chain' and is the integration stream's
         tamper-evidence guarantee.
      3. If the record is being finalized for public release (see
         _PUBLIC_RELEASE_CLASSIFICATIONS) AND scan_record returned blocking
         flags, raise UnsafeFinalizationError BEFORE hashing. We do not
         seal an unsafe record into the chain.
      4. attach_hash_chain() seals the record. Order: flags -> hash. After
         this point any further mutation invalidates record_hash and
         verify_hash_chain() will reject it.
    """
    prepared = deepcopy(record)
    prepared.setdefault("recommendation_refs", [])
    prepared.setdefault("safety_flags", [])
    prepared = apply_safety_flags(prepared)

    classification = str(prepared.get("release_classification", "")).strip().lower()
    if classification in _PUBLIC_RELEASE_CLASSIFICATIONS:
        # Re-scan against the post-flag-attachment record so we catch any
        # finalize-time additions (defense-in-depth; apply_safety_flags
        # already did this scan, but we want to refuse-to-seal explicitly).
        flags = scan_record(prepared)
        blocks = blocking_flags(flags)
        if blocks:
            raise UnsafeFinalizationError(
                record_id=str(prepared.get("id", "<unknown>")),
                flag_rules=[flag.rule for flag in blocks],
            )

    return attach_hash_chain(prepared, previous_hash=previous_hash)
