from __future__ import annotations

from copy import deepcopy
from typing import Any

from .io import canonical_json, sha256_bytes

CANONICALIZATION = "json-v1-sorted-no-hash-chain"


def record_payload(record: dict[str, Any]) -> dict[str, Any]:
    payload = deepcopy(record)
    payload.pop("hash_chain", None)
    return payload


def hash_record(record: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(record_payload(record)))


def attach_hash_chain(record: dict[str, Any], previous_hash: str | None = None) -> dict[str, Any]:
    chained = deepcopy(record)
    chained.pop("hash_chain", None)
    chained["hash_chain"] = {
        "canonicalization": CANONICALIZATION,
        "previous_hash": previous_hash,
        "record_hash": hash_record(chained),
    }
    return chained


def verify_hash_chain(record: dict[str, Any]) -> list[str]:
    chain = record.get("hash_chain")
    if not isinstance(chain, dict):
        return ["missing hash_chain"]
    errors: list[str] = []
    if chain.get("canonicalization") != CANONICALIZATION:
        errors.append("unsupported hash-chain canonicalization")
    expected = hash_record(record)
    if chain.get("record_hash") != expected:
        errors.append(f"record hash mismatch: expected {expected}, found {chain.get('record_hash')}")
    previous_hash = chain.get("previous_hash")
    if previous_hash is not None and not isinstance(previous_hash, str):
        errors.append("previous_hash must be null or sha256 string")
    return errors
