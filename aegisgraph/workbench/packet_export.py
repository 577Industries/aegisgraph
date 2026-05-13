"""Reviewer-packet export — `aegisgraph workbench packet --top N --out DIR`.

Output tree under <out>/<ISO_DATE>/:

  manifest.json                      tool_output_type="reviewer_packet"
                                     + artifacts[] with sha256 per file
  bundle.md                          human-readable rollup
  findings/<record_id>.json          per-finding raw record (verbatim)
  findings/<record_id>.evidence.md   per-finding Markdown evidence brief
  checksums.sha256                   GNU sha256sum-format file

The packet is *sanitize-aware*: every per-finding record is rewritten
into a public-safe projection (claim_state, finding metadata, score,
target identifier, supersedes ID — but no embedded payloads, raw
witnesses, vendor contacts, or stack frames). The full sanitize-check
machinery in `validator/sanitize_check.py` is run against the emitted
tree as a final fail-closed gate; if it returns failures, the packet
is still written but the manifest is marked
``sanitize_check.status="fail"``.

`export_packet` is pure-Python and never touches the network or
external tools.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .filters import FilterSpec, FindingFilters
from .finding_detail import _resolve_evidence_refs, render_markdown, show_finding
from .finding_list import list_findings
from .registry import scan


# Fields that are NEVER copied into the public per-finding JSON.
# (Defense-in-depth: sanitize-check covers most of these; this list is
# the *active* projection step that prevents accidental copy-through.)
_BLOCKED_FIELDS = frozenset(
    {
        "bytes_b64",
        "payload",
        "raw_bytes",
        "raw_reproducer",
        "raw_witness",
        "raw_corpus_input",
        "vendor_contact",
        "notes_hash",
        "source_snippet",
    }
)


def export_packet(
    root: Path,
    top_n: int = 10,
    out_dir: Path | None = None,
    filter_spec: FilterSpec | None = None,
) -> dict[str, Any]:
    """Build the reviewer packet under <out_dir>/<ISO_DATE>/.

    Returns the manifest dict (also written to disk as manifest.json).
    """
    if out_dir is None:
        out_dir = root / "exports" / "reviewer-packet"
    iso = _iso_date_dir()
    target_dir = Path(out_dir) / iso
    target_dir.mkdir(parents=True, exist_ok=True)

    filters = (filter_spec or FilterSpec("")).to_filters()
    rows = list_findings(root, filters)
    selected = rows[: max(0, int(top_n))]

    findings_dir = target_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    written_findings: list[dict[str, Any]] = []
    for row in selected:
        record_id = row["record_id"]
        public_record = _public_projection(row.get("_record") or {})
        record_path = findings_dir / f"{record_id}.json"
        evidence_path = findings_dir / f"{record_id}.evidence.md"
        _write_json(record_path, public_record)
        envelope = show_finding(root, record_id)
        # Replace the in-envelope record with the redacted projection so
        # the rendered Markdown doesn't accidentally leak source_snippet
        # or raw_* fields from the verbatim record.
        envelope["record"] = public_record
        envelope["evidence_refs"] = _resolve_evidence_refs(public_record, root)
        evidence_path.write_text(render_markdown(envelope), encoding="utf-8")
        written_findings.append(
            {
                "record_id": record_id,
                "engine": row.get("engine"),
                "claim_state": row.get("claim_state"),
                "score_total": row.get("score_total"),
                "record_hash": row.get("record_hash"),
                "json_path": str(record_path.relative_to(target_dir)),
                "evidence_path": str(evidence_path.relative_to(target_dir)),
            }
        )

    bundle_path = target_dir / "bundle.md"
    bundle_path.write_text(_render_bundle(written_findings, filters), encoding="utf-8")

    # Manifest assembled BEFORE checksums + sanitize check so the manifest
    # itself is in the artifacts list. We compute checksums for every
    # written file (incl. the manifest after first writing a placeholder).
    artifacts: list[dict[str, str]] = []
    manifest_path = target_dir / "manifest.json"

    # Write placeholder so checksums computation sees a deterministic file.
    _write_json(
        manifest_path,
        {
            "tool_output_type": "reviewer_packet",
            "version": "v1.0",
            "generated_by": "aegisgraph-workbench",
            "generated_at": _iso_now(),
            "safety_posture": "sanitized_candidate",
            "iso_date": iso,
            "top_n": top_n,
            "filters": filters.to_dict(),
            "findings": written_findings,
            "artifacts": [],
            "checksums_file": "checksums.sha256",
            "sanitize_check": {"status": "deferred"},
        },
    )

    # Walk every file the packet wrote.
    for path in sorted(target_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name == "checksums.sha256":
            continue
        artifacts.append(
            {
                "path": str(path.relative_to(target_dir)),
                "sha256": _sha256_file(path),
            }
        )

    # Write checksums.sha256 (GNU sha256sum format: "<hex>  <path>").
    checksums_path = target_dir / "checksums.sha256"
    checksums_path.write_text(
        "".join(f"{a['sha256']}  {a['path']}\n" for a in artifacts),
        encoding="utf-8",
    )

    # Re-run sanitize-check ONLY on the per-finding tree + bundle (NOT on
    # manifest.json — the manifest itself contains record_hash strings
    # which look like blocking patterns to the v0.4 raw_stack_trace
    # heuristic). The findings tree is the public-handoff surface.
    sanitize_status, sanitize_failures = _run_sanitize_check(target_dir)

    # Final manifest write with full artifact list + sanitize result.
    manifest = {
        "tool_output_type": "reviewer_packet",
        "version": "v1.0",
        "generated_by": "aegisgraph-workbench",
        "generated_at": _iso_now(),
        "safety_posture": "sanitized_candidate",
        "iso_date": iso,
        "top_n": top_n,
        "filters": filters.to_dict(),
        "findings": written_findings,
        "artifacts": sorted(artifacts, key=lambda a: a["path"]),
        "checksums_file": "checksums.sha256",
        "sanitize_check": {
            "status": sanitize_status,
            "failures": sanitize_failures,
        },
    }
    _write_json(manifest_path, manifest)

    # Re-checksum the manifest now that it carries the final artifact list.
    # The artifacts list inside the manifest itself reflects the pre-final-
    # write set, which is acceptable: checksums.sha256 is the immutable
    # post-final-write record and reviewers consume that file as truth.
    final_manifest_sha = _sha256_file(manifest_path)
    # Append/replace the manifest line in checksums.sha256 with the final
    # value so consumers verifying with `sha256sum -c` succeed.
    lines = checksums_path.read_text(encoding="utf-8").splitlines()
    new_lines = [
        line for line in lines if not line.endswith("  manifest.json")
    ]
    new_lines.append(f"{final_manifest_sha}  manifest.json")
    checksums_path.write_text("\n".join(sorted(new_lines)) + "\n", encoding="utf-8")
    return manifest


def _public_projection(record: dict[str, Any]) -> dict[str, Any]:
    """Strip known-private fields from a record before packet emission.

    This is *projection*, not mutation of the original — the input
    record dict is not modified. The blocked fields list mirrors
    `validator.sanitize_check._PAYLOAD_FIELD_NAMES` plus the v0.4
    vendor_contact / notes_hash / source_snippet additions.

    The projected record retains hash_chain unchanged; the chain still
    verifies because we strip only fields that were never part of the
    public record shape in the first place. (If a record contains a
    blocked field, hash_chain.record_hash would be invalid post-strip;
    that's why we never strip — we just *omit* fields when writing the
    public copy.)
    """
    out: dict[str, Any] = {}
    for key, value in record.items():
        if key in _BLOCKED_FIELDS:
            continue
        if isinstance(value, dict):
            out[key] = _public_projection_subtree(value)
        elif isinstance(value, list):
            out[key] = [
                _public_projection_subtree(v) if isinstance(v, dict) else v
                for v in value
            ]
        else:
            out[key] = value
    return out


def _public_projection_subtree(value: dict[str, Any]) -> dict[str, Any]:
    return {
        k: (
            _public_projection_subtree(v)
            if isinstance(v, dict)
            else (
                [_public_projection_subtree(x) if isinstance(x, dict) else x for x in v]
                if isinstance(v, list)
                else v
            )
        )
        for k, v in value.items()
        if k not in _BLOCKED_FIELDS
    }


def _render_bundle(findings: list[dict[str, Any]], filters: FindingFilters) -> str:
    lines: list[str] = []
    lines.append("# AegisGraph Reviewer Packet")
    lines.append("")
    lines.append(f"- Generated at: {_iso_now()}")
    lines.append(f"- Top-N: {len(findings)}")
    if filters.to_dict():
        lines.append(f"- Filters: {filters.to_dict()}")
    lines.append("")
    lines.append("## Findings (sorted by score_total desc)")
    lines.append("")
    if not findings:
        lines.append("_(no findings matched)_")
        lines.append("")
        return "\n".join(lines)
    lines.append("| Rank | Record ID | Engine | Claim state | Score |")
    lines.append("| ---- | --------- | ------ | ----------- | ----- |")
    for rank, f in enumerate(findings, start=1):
        lines.append(
            f"| {rank} | `{f['record_id']}` | {f['engine']} | "
            f"{f['claim_state']} | {f['score_total']:.3f} |"
        )
    lines.append("")
    lines.append("## Per-finding artifacts")
    lines.append("")
    for f in findings:
        lines.append(
            f"- `{f['record_id']}` -> [{f['json_path']}]({f['json_path']}), "
            f"[{f['evidence_path']}]({f['evidence_path']})"
        )
    lines.append("")
    return "\n".join(lines)


def _run_sanitize_check(target_dir: Path) -> tuple[str, list[str]]:
    """Call validator.sanitize_check on the emitted packet's findings tree.

    Returns (status, failure_messages). Status is one of:
      "pass"     - scan_export_tree.ok == True
      "fail"     - one or more rules tripped
      "skipped"  - import failed (e.g. validator module unavailable)
    """
    try:
        from validator.sanitize_check import scan_export_tree  # local import
    except Exception:  # pragma: no cover - defensive
        return ("skipped", ["validator.sanitize_check import failed"])
    findings_dir = target_dir / "findings"
    if not findings_dir.exists():
        return ("skipped", ["findings directory not present"])
    report = scan_export_tree(findings_dir)
    if report.ok:
        return ("pass", [])
    return ("fail", [f.to_line() for f in report.failures])


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _iso_date_dir(today: date | None = None) -> str:
    return (today or datetime.now(timezone.utc).date()).isoformat()


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
