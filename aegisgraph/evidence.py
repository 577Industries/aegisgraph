from __future__ import annotations

from copy import deepcopy
from typing import Any

from .constants import STATIC_GENERATED_AT
from .hashchain import attach_hash_chain
from .io import sha256_text
from .safety import apply_safety_flags


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
    prepared = deepcopy(record)
    prepared.setdefault("recommendation_refs", [])
    prepared.setdefault("safety_flags", [])
    prepared = apply_safety_flags(prepared)
    return attach_hash_chain(prepared, previous_hash=previous_hash)
