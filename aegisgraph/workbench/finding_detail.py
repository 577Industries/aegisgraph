"""`aegisgraph workbench show` — single-record detail view.

`show_finding(root, record_id)` returns a dict envelope:

  {
    "record": <the full AG-* record dict from disk>,
    "engine": <engine bucket>,
    "source_path": <repo-relative path of the source file>,
    "supersedes_chain": [
        # walk prior -> ... -> oldest; each entry includes record_id,
        # claim_state, record_hash, source_path
    ],
    "evidence_refs": [
        # each entry is the original evidence_ref dict plus a resolved
        # `on_disk_paths` list (best-effort tool-output discovery via the
        # `evidence_refs[*].command` + `evidence_refs[*].tool` hints)
    ],
  }

This is intentionally a read-only view; it does not mutate the record
or touch the hash chain.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .registry import FindingRow, _record_id, find_record, scan


def show_finding(root: Path, record_id: str) -> dict[str, Any]:
    """Resolve a single record and walk its supersedes chain.

    Returns an empty record when the record is not found (the CLI
    caller renders an explicit "not found" message).
    """
    row = find_record(root, record_id)
    if row is None:
        return {
            "record": None,
            "engine": None,
            "source_path": None,
            "supersedes_chain": [],
            "evidence_refs": [],
            "not_found": True,
        }
    all_rows = scan(root)
    by_id = {r.record_id: r for r in all_rows}
    chain = _walk_supersedes(row, by_id)
    refs = _resolve_evidence_refs(row.record, root)
    return {
        "record": row.record,
        "record_id": row.record_id,
        "engine": row.engine,
        "claim_state": row.claim_state,
        "score_total": row.score_total,
        "source_path": row.source_path,
        "record_hash": row.record_hash,
        "supersedes": row.supersedes,
        "supersedes_chain": chain,
        "evidence_refs": refs,
    }


def _walk_supersedes(row: FindingRow, by_id: dict[str, FindingRow]) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    visited: set[str] = set()
    current: FindingRow | None = row
    # Walk parent -> grandparent -> ... — the current row's supersedes
    # field, if present, points to the *prior* record that this one
    # promotes from. The chain stops when supersedes is None or we
    # encounter a cycle (defensive).
    while current is not None and current.supersedes:
        sid = current.supersedes
        if sid in visited:
            break
        visited.add(sid)
        parent = by_id.get(sid)
        if parent is None:
            chain.append({
                "record_id": sid,
                "claim_state": None,
                "record_hash": None,
                "source_path": None,
                "not_found": True,
            })
            break
        chain.append({
            "record_id": parent.record_id,
            "claim_state": parent.claim_state,
            "record_hash": parent.record_hash,
            "source_path": parent.source_path,
        })
        current = parent
    return chain


def _resolve_evidence_refs(record: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    """Best-effort resolution of evidence_refs to on-disk paths.

    For each evidence_ref we look for files whose path contains the
    `command` substring (e.g. `make polydiff-regression` -> probably
    nothing matches, but `extraction/adapters/assemble.py` will match)
    and surface them. Misses are not fatal — the resolver returns an
    empty `on_disk_paths` for orphan refs.
    """
    refs = record.get("evidence_refs")
    if not isinstance(refs, list):
        return []
    out: list[dict[str, Any]] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        enriched = dict(ref)
        enriched["on_disk_paths"] = _candidate_paths(ref, root)
        out.append(enriched)
    return out


def _candidate_paths(ref: dict[str, Any], root: Path) -> list[str]:
    """Find files whose repo-relative path includes a token from the ref."""
    hints: list[str] = []
    for key in ("command", "tool"):
        value = ref.get(key)
        if isinstance(value, str) and value:
            hints.append(value)
    matches: list[str] = []
    seen: set[str] = set()
    for hint in hints:
        # The hint may be a make target ("make polydiff-regression"); we
        # extract path-like tokens by splitting on whitespace and slashes.
        tokens = [t for t in hint.replace("\\", "/").split() if "/" in t or "." in t]
        for token in tokens:
            for path in root.rglob(token):
                if not path.is_file():
                    continue
                rel = str(path.relative_to(root))
                if rel not in seen:
                    matches.append(rel)
                    seen.add(rel)
            if len(matches) >= 5:
                break
        if len(matches) >= 5:
            break
    return matches[:5]


def render_markdown(envelope: dict[str, Any]) -> str:
    """Render the envelope as reviewer-readable Markdown."""
    if envelope.get("not_found"):
        return "## Finding not found\n\n(no record matched the supplied ID)\n"
    record = envelope.get("record") or {}
    rid = envelope.get("record_id") or _record_id(record) or "<unknown>"
    lines: list[str] = []
    lines.append(f"# {rid}")
    lines.append("")
    lines.append(f"- Engine: {envelope.get('engine')}")
    lines.append(f"- Claim state: {envelope.get('claim_state')}")
    lines.append(f"- Score (total): {envelope.get('score_total')}")
    lines.append(f"- Source path: `{envelope.get('source_path')}`")
    lines.append(f"- Record hash: `{envelope.get('record_hash')}`")
    if envelope.get("supersedes"):
        lines.append(f"- Supersedes: `{envelope.get('supersedes')}`")
    target = record.get("target")
    if isinstance(target, dict):
        lines.append(f"- Target: {target.get('name')} (`{target.get('repo_url')}` @ `{target.get('commit')}`)")
    elif isinstance(record.get("target_id"), str):
        lines.append(f"- Target id: `{record.get('target_id')}`")
    limitations = record.get("limitations")
    if isinstance(limitations, str) and limitations:
        lines.append("")
        lines.append("## Limitations")
        lines.append("")
        lines.append(limitations)
    refs = envelope.get("evidence_refs") or []
    if refs:
        lines.append("")
        lines.append("## Evidence references")
        lines.append("")
        for ref in refs:
            ref_id = ref.get("id") or "<no-id>"
            tool = ref.get("tool") or ""
            output_hash = ref.get("output_hash") or ""
            lines.append(f"- `{ref_id}` (tool={tool}, output_hash=`{output_hash}`)")
            for path in ref.get("on_disk_paths") or []:
                lines.append(f"    - `{path}`")
    chain = envelope.get("supersedes_chain") or []
    if chain:
        lines.append("")
        lines.append("## Supersedes chain")
        lines.append("")
        for entry in chain:
            cs = entry.get("claim_state") or "<unknown>"
            rh = entry.get("record_hash") or ""
            lines.append(f"- `{entry.get('record_id')}` claim_state={cs} record_hash=`{rh}`")
    lines.append("")
    return "\n".join(lines)
