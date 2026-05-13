"""Hash-chained append-only disclosure-event ledger.

Per ADR-0014: each line is one canonical-JSON event with a hash chain
linking to the previous line via `hash_chain.previous_hash`.

The ledger reuses the same canonicalization primitives as evidence
records (`aegisgraph.hashchain` + `aegisgraph.io.canonical_json`), so a
reviewer running `verify_chain()` exercises the same code path as
`tests/test_hashchain.py`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from aegisgraph.hashchain import attach_hash_chain, hash_record, verify_hash_chain
from aegisgraph.io import canonical_json, repo_root


DEFAULT_LEDGER_PATH_REL = "aegisgraph/disclosure/ledger.jsonl"


def ledger_path(root: Path | None = None) -> Path:
    """Return the on-disk location of the disclosure ledger."""
    base = root or repo_root()
    return base / DEFAULT_LEDGER_PATH_REL


def read_all(path: Path | None = None) -> list[dict]:
    """Return all events in append order. Empty list if file absent or empty."""
    target = path or ledger_path()
    if not target.exists():
        return []
    events: list[dict] = []
    with target.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                events.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"disclosure ledger line {line_no} is not valid JSON: {exc}"
                ) from exc
    return events


def _last_record_hash(path: Path) -> str | None:
    """Return the record_hash of the last entry, or None if file is empty."""
    if not path.exists():
        return None
    last_event: dict | None = None
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            last_event = json.loads(stripped)
    if last_event is None:
        return None
    chain = last_event.get("hash_chain", {})
    return chain.get("record_hash")


def append(event: dict, path: Path | None = None) -> dict:
    """Append a new event to the ledger.

    Computes the hash chain so this entry's `previous_hash` equals the
    prior entry's `record_hash`. Returns the finalized event (with
    `hash_chain` block attached). The caller is responsible for
    finalizing `provenance`, `safety_flags`, and validating against
    `schema/disclosure-event.schema.json` BEFORE calling append; this
    function does not perform schema validation.

    The ledger file is created if absent. Writes one canonical-JSON
    line followed by a newline.
    """
    target = path or ledger_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    previous = _last_record_hash(target)
    finalized = attach_hash_chain(event, previous_hash=previous)
    line = canonical_json(finalized) + b"\n"
    with target.open("ab") as fh:
        fh.write(line)
    return finalized


def verify_chain(path: Path | None = None) -> list[str]:
    """Walk the ledger line-by-line and verify the hash chain.

    Returns a list of human-readable error messages. Empty list = chain
    is intact and every entry's hash_chain block verifies.
    """
    events = read_all(path)
    errors: list[str] = []
    expected_previous: str | None = None
    for index, event in enumerate(events):
        chain = event.get("hash_chain", {})
        actual_previous = chain.get("previous_hash")
        if actual_previous != expected_previous:
            errors.append(
                f"line {index + 1}: previous_hash mismatch — "
                f"expected {expected_previous!r}, found {actual_previous!r}"
            )
        record_errors = verify_hash_chain(event)
        for msg in record_errors:
            errors.append(f"line {index + 1}: {msg}")
        expected_previous = chain.get("record_hash")
    return errors


def iter_events(path: Path | None = None) -> Iterator[dict]:
    """Yield each event in append order without materializing the full list."""
    target = path or ledger_path()
    if not target.exists():
        return
    with target.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            yield json.loads(stripped)
