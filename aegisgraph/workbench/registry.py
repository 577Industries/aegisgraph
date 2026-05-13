"""On-disk scan for AG-* records.

Scans the six engine-output directories for hash-chained records:

  - extraction/output/                     -> AG-EV-*
  - polydiff/evidence/                     -> AG-EV-* (regression bundle)
                                              + AG-DIS-* (disagreements)
  - polydiff/families/<family>/evidence/   -> AG-DIS-*
  - aegisgraph/harnessgen/runs/            -> AG-CRASH-* (+ run bundles)
  - aegisgraph/invariants/output/          -> AG-IV-*
  - aegisgraph/crosssma/evidence/          -> AG-XSMA-*
  - aegisgraph/disclosure/ledger.jsonl     -> AG-DISC-*

Each record is normalized to a flat row shape (FindingRow) with the
fields the workbench consumes (record_id, engine, target, claim_state,
score_total, supersedes, hash, path). The original record dict is also
attached as `_record` so `show_finding` can return the full envelope
without a second disk read.

No live target probing; no network. This module reads bytes from disk
and parses JSON / JSONL only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


# Map ID-prefix -> engine bucket. We prefer the prefix because it is the
# stable, schema-pinned discriminator; the record may also carry
# discovery_engine, which we read as a fallback / cross-check.
_PREFIX_TO_ENGINE: dict[str, str] = {
    "AG-EV-": "extraction",  # default for raw AG-EV-*; overridden via discovery_engine below
    "AG-DIS-": "polydiff",
    "AG-CRASH-": "harnessgen",
    "AG-IV-": "invariantcheck",
    "AG-XSMA-": "crosssma",
    "AG-DISC-": "disclosure",
    "AG-FIND-": "manual",  # findings (defensive recommendations) live in the same envelope
}


# Glob patterns rooted at the repo. Each pattern's matching files are
# parsed as JSON (or JSONL when `is_jsonl=True`) and walked for records.
@dataclass(frozen=True)
class _ScanLocation:
    pattern: str
    is_jsonl: bool = False


_SCAN_LOCATIONS: tuple[_ScanLocation, ...] = (
    _ScanLocation("extraction/output/**/*.json"),
    _ScanLocation("polydiff/evidence/**/*.json"),
    _ScanLocation("polydiff/families/**/evidence/**/*.json"),
    _ScanLocation("reprochain/evidence/**/*.json"),
    _ScanLocation("aegisgraph/harnessgen/runs/**/*.json"),
    _ScanLocation("aegisgraph/harnessgen/evidence/**/*.json"),
    _ScanLocation("aegisgraph/invariants/output/**/*.json"),
    _ScanLocation("aegisgraph/invariants/evidence/**/*.json"),
    _ScanLocation("aegisgraph/crosssma/evidence/**/*.json"),
    _ScanLocation("aegisgraph/crosssma/output/**/*.json"),
    _ScanLocation("aegisgraph/workbench/promotions/**/*.json"),
    _ScanLocation("aegisgraph/disclosure/ledger.jsonl", is_jsonl=True),
)


@dataclass
class FindingRow:
    """Flat projection of an AG-* record for table rendering + filtering."""

    record_id: str
    engine: str
    target: str
    claim_state: str
    score_total: float
    supersedes: str | None
    record_hash: str
    source_path: str
    # The full record envelope (verbatim from disk). `_record` is the
    # source of truth; the flat fields above are convenience projections.
    record: dict[str, Any] = field(default_factory=dict)

    def to_row_dict(self) -> dict[str, Any]:
        """Dict projection used by `list_findings` + filtering."""
        return {
            "record_id": self.record_id,
            "engine": self.engine,
            "discovery_engine": self.record.get("discovery_engine") or self.engine,
            "target": self.record.get("target") or self.record.get("target_id"),
            "target_id": self.record.get("target_id"),
            "claim_state": self.claim_state,
            "score_total": self.score_total,
            "supersedes": self.supersedes,
            "record_hash": self.record_hash,
            "source_path": self.source_path,
            "_record": self.record,
        }


def detect_engine(record: dict[str, Any]) -> str:
    """Return the engine bucket for a record.

    Priority:
      1. `discovery_engine` field if present and non-null.
      2. ID-prefix lookup.
      3. "unknown" sentinel.
    """
    eng = record.get("discovery_engine")
    if isinstance(eng, str) and eng:
        return eng
    rid = _record_id(record)
    if rid:
        for prefix, engine in _PREFIX_TO_ENGINE.items():
            if rid.startswith(prefix):
                return engine
    return "unknown"


def _record_id(record: dict[str, Any]) -> str | None:
    for key in ("id", "entry_id", "violation_id", "crash_id", "candidate_id", "disagreement_id"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _score_total(record: dict[str, Any]) -> float:
    score = record.get("score_vector")
    if isinstance(score, dict):
        total = score.get("total")
        if isinstance(total, (int, float)):
            return float(total)
    return 0.0


def _claim_state(record: dict[str, Any]) -> str:
    state = record.get("claim_state")
    if isinstance(state, str) and state:
        return state
    # AG-DIS / AG-CRASH / AG-IV / AG-XSMA / AG-DISC don't carry claim_state
    # directly — they're per-finding lifecycle markers. Engineering norm:
    # default to "observed" for unstated records so the workbench surfaces
    # them in the reviewer's queue.
    return "observed"


def _record_hash(record: dict[str, Any]) -> str:
    chain = record.get("hash_chain")
    if isinstance(chain, dict):
        rh = chain.get("record_hash")
        if isinstance(rh, str):
            return rh
    return ""


def _records_from_document(document: Any) -> list[dict[str, Any]]:
    """Pull AG-* records out of a JSON document.

    Mirrors `validator.sanitize_check._records_from_document` so we
    apply consistent record-detection logic everywhere. Accepts:

      - A top-level record (has `id` starting with AG-).
      - A top-level dict with `records` / `evidence_records` / `findings`
        / `disclosure_events` / `invariant_violations` / `crashes` /
        `disagreements` / `discovery_runs` / `cross_target_candidates`
        lists.
    """
    if not isinstance(document, dict):
        return []
    out: list[dict[str, Any]] = []
    if _has_ag_id(document):
        out.append(document)
    for key in (
        "records",
        "evidence_records",
        "findings",
        "disclosure_events",
        "invariant_violations",
        "crashes",
        "disagreements",
        "discovery_runs",
        "cross_target_candidates",
    ):
        items = document.get(key)
        if isinstance(items, list):
            out.extend(r for r in items if isinstance(r, dict) and _has_ag_id(r))
    return out


def _has_ag_id(record: dict[str, Any]) -> bool:
    rid = _record_id(record)
    if not rid:
        return False
    return any(rid.startswith(prefix) for prefix in _PREFIX_TO_ENGINE)


def _read_jsonl_records(path: Path) -> Iterable[dict[str, Any]]:
    """Yield decoded JSON objects, one per non-empty line."""
    if not path.exists() or not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                # Malformed line — skip silently; the validator pass will
                # catch chain-integrity issues separately.
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out


def _iter_paths(root: Path, locations: tuple[_ScanLocation, ...]) -> Iterable[tuple[_ScanLocation, Path]]:
    for location in locations:
        for path in sorted(root.glob(location.pattern)):
            if path.is_file():
                yield location, path


def _supersedes(record: dict[str, Any]) -> str | None:
    sup = record.get("supersedes")
    if isinstance(sup, str) and sup:
        return sup
    return None


def _build_row(record: dict[str, Any], engine_hint: str, source_path: str) -> FindingRow | None:
    rid = _record_id(record)
    if not rid:
        return None
    engine = engine_hint or detect_engine(record)
    target = _target_label(record)
    return FindingRow(
        record_id=rid,
        engine=engine,
        target=target,
        claim_state=_claim_state(record),
        score_total=_score_total(record),
        supersedes=_supersedes(record),
        record_hash=_record_hash(record),
        source_path=source_path,
        record=record,
    )


def _target_label(record: dict[str, Any]) -> str:
    """Human-readable target label for a row.

    Supports the heterogeneous shapes:
      - AG-EV-*: target.name (dict)
      - AG-IV-* / AG-CRASH-*: target_id (string)
      - AG-XSMA-*: target_findings list -> "(N targets)"
      - AG-DIS-*: implementations_disagreeing list -> first impl name
      - AG-DISC-*: finding_id (link back to source record)
    """
    target = record.get("target")
    if isinstance(target, dict):
        name = target.get("name")
        if isinstance(name, str) and name:
            return name
    target_id = record.get("target_id")
    if isinstance(target_id, str) and target_id:
        return target_id
    targets = record.get("target_findings")
    if isinstance(targets, list) and targets:
        return f"({len(targets)} targets)"
    impls = record.get("implementations_disagreeing")
    if isinstance(impls, list) and impls:
        return f"({len(impls)} impls: {impls[0]})"
    finding_id = record.get("finding_id")
    if isinstance(finding_id, str) and finding_id:
        return f"->{finding_id}"
    return "<unknown>"


def scan(root: Path) -> list[FindingRow]:
    """Scan the on-disk record landscape and return a flat row list.

    Rows are deduplicated by record_id. When duplicate IDs collide (e.g.
    the same record copied into two locations during a packet rebuild)
    the row from the lexically first source path wins; ties are stable.

    Returns rows in source-path lexical order — the caller is responsible
    for any further sort (e.g. score-descending for `packet`).
    """
    rows: list[FindingRow] = []
    seen: set[str] = set()
    for location, path in _iter_paths(root, _SCAN_LOCATIONS):
        rel = str(path.relative_to(root))
        if location.is_jsonl:
            for record in _read_jsonl_records(path):
                row = _build_row(record, engine_hint=detect_engine(record), source_path=rel)
                if row is None or row.record_id in seen:
                    continue
                rows.append(row)
                seen.add(row.record_id)
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for record in _records_from_document(document):
            row = _build_row(record, engine_hint=detect_engine(record), source_path=rel)
            if row is None or row.record_id in seen:
                continue
            rows.append(row)
            seen.add(row.record_id)
    return rows


def find_record(root: Path, record_id: str) -> FindingRow | None:
    """Locate a single record by ID; returns None if absent.

    Lazy implementation: scans the same locations, returns the first
    match. For workbench command latency this is acceptable; future
    optimization can add a JSON index file.
    """
    for row in scan(root):
        if row.record_id == record_id:
            return row
    return None
