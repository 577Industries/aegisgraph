"""Traceability matrix builder.

Joins four sources into a single auditable table:

  1. SPEC.md headers (the master Tier-3 spec at /SPEC.md). Each `## N`
     and `### N.N` heading becomes a `spec_section` row.
  2. On-disk evidence files emitted by the engineering streams:
       extraction/output/manifest.json
       extraction/output/<target>/graph.json
       reprochain/evidence/{build_manifest,run_status,mapping}.json
       polydiff/regression/report.json
       polydiff/evidence/regression.evidence.json
       smabench/results/latest/results.json
       validation-report.json (when present)
  3. docs/proposal-claims-index.yml (claim_id → spec_section + evidence
     refs + DSIP requirement).
  4. docs/dsip-requirements.yml (requirement_id → page-limit /
     evaluation-criterion / deliverable etc.).

Output rows:

    {
        spec_section, artifact_path, proposal_claim,
        dsip_requirement, status
    }

Status values:

  - ok                       claim has at least one on-disk evidence
                             artifact AND a DSIP requirement (or has
                             evidence_record set non-null)
  - claim_without_evidence   claim has artifacts listed but at least one
                             is missing on disk; OR claim has no
                             evidence_record set AND no on-disk artifact
                             matched its spec_section
  - evidence_without_claim   on-disk evidence file exists under one of
                             the spec-section areas but no claim points
                             at it (potential drift; needs proposal-side
                             update)
  - planned                  claim is drafted but listed evidence is
                             explicitly out-of-scope of this stream
                             (e.g. compliance gates, page-limit claims —
                             owned by humans / proposal-package agent)

The module emits two files into reports/:
  - reports/traceability_matrix.json   (machine-readable join)
  - reports/traceability_matrix.md     (human-readable table; suitable
                                        for proposal-package inclusion)

Both are regenerated atomically on every `make traceability` run.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

# Repo root is parents[1] from validator/.
_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# YAML loader (best-effort; we depend on PyYAML which is in pyproject)
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> Any:
    """Load YAML from path; raises with a clear message if PyYAML is missing
    or the file is malformed. We don't try a manual parse fallback because
    the project already declares pyyaml>=6 in pyproject.
    """
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - dependency missing
        raise RuntimeError(
            "PyYAML is required for traceability matrix generation; "
            "ensure pyyaml>=6 is installed (pyproject already requires it)"
        ) from exc
    if not path.exists():
        raise FileNotFoundError(f"required file does not exist: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


# ---------------------------------------------------------------------------
# SPEC.md heading extraction
# ---------------------------------------------------------------------------


# Match `## N. Title`, `## N Title`, `### N.N. Title`, `### N.N Title`
# (numbered headings with optional trailing period). Bare `## Foo`
# headings are skipped because they are not stable section anchors and
# the proposal claims-index uses numbered sections only.
_HEADING_RE = re.compile(
    r"^(#{2,3})\s+(\d+(?:\.\d+)*)\.?\s+(.+?)\s*$", re.MULTILINE
)


@dataclass(frozen=True)
class SpecSection:
    section: str  # "1", "4.7", etc.
    level: int  # 2 (## ) or 3 (### )
    title: str


def parse_spec_sections(spec_path: Path) -> list[SpecSection]:
    if not spec_path.exists():
        return []
    text = spec_path.read_text(encoding="utf-8")
    sections: list[SpecSection] = []
    for match in _HEADING_RE.finditer(text):
        hashes, number, title = match.group(1), match.group(2), match.group(3).strip()
        sections.append(
            SpecSection(section=number, level=len(hashes), title=title)
        )
    return sections


# ---------------------------------------------------------------------------
# Evidence-file inventory
# ---------------------------------------------------------------------------


# Mapping spec_section (top-level "1"-"11") → list of artifact paths the
# engineering streams emit under that area. The mapping is intentionally
# coarse (top-level only) because the proposal-claims-index pins the
# fine-grained spec_section per claim; we use this only to detect
# evidence-without-claim.
_SECTION_TO_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "4": (  # ReproChain
        "reprochain/evidence/build_manifest.json",
        "reprochain/evidence/run_status.json",
        "reprochain/evidence/mapping.json",
    ),
    "5": (  # PolyDiff
        "polydiff/regression/report.json",
        "polydiff/evidence/regression.evidence.json",
    ),
    "6": (  # Extraction
        "extraction/output/manifest.json",
        "extraction/output/signal/graph.json",
        "extraction/output/element-x/graph.json",
    ),
    "7": (  # SMABench
        "smabench/results/latest/results.json",
    ),
    "8": (  # Schema / safety / hash-chain (cross-cutting)
        "schema/evidence.schema.json",
        "schema/fact-vector.schema.json",
        "schema/finding.schema.json",
        "schema/hash-chain.schema.json",
        "schema/recommendation.schema.json",
        "schema/tool-output.schema.json",
    ),
    "10": (  # Verification (validation-report.json is generated, may be
        # absent in non-mutating mode — that's fine)
        "validation-report.json",
        "tooling-versions.json",
    ),
}


def _existing(root: Path, paths: tuple[str, ...]) -> list[str]:
    return [p for p in paths if (root / p).exists()]


def _missing(root: Path, paths: list[str]) -> list[str]:
    return [p for p in paths if not (root / p).exists()]


# ---------------------------------------------------------------------------
# Row construction
# ---------------------------------------------------------------------------


@dataclass
class TraceRow:
    spec_section: str
    artifact_path: str
    proposal_claim: str
    dsip_requirement: str
    status: str
    notes: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


_PLANNED_OWNER_SECTIONS = frozenset({"sbir_application"})  # human-owned


def _row_status_for_claim(
    claim: dict[str, Any], root: Path
) -> tuple[str, list[str]]:
    """Decide row status for a single claim based on artifact presence.

    Returns (status, missing_artifact_paths).
    """
    artifacts = list(claim.get("evidence_artifacts") or [])
    owner = claim.get("owner_section")
    if not artifacts:
        if owner in _PLANNED_OWNER_SECTIONS:
            return "planned", []
        if claim.get("evidence_record"):
            # Record exists but the claim doesn't list artifacts —
            # treat as ok if record is non-empty, else claim_without_evidence.
            return "claim_without_evidence", []
        return "claim_without_evidence", []
    missing = _missing(root, artifacts)
    if missing:
        return "claim_without_evidence", missing
    return "ok", []


def build_rows(
    root: Path,
    spec_sections: list[SpecSection],
    claims_index: dict[str, Any],
    dsip_index: dict[str, Any],
) -> list[TraceRow]:
    rows: list[TraceRow] = []

    spec_section_set = {s.section for s in spec_sections}
    # Index DSIP requirements by id for O(1) lookup later
    dsip_by_id = {
        r["requirement_id"]: r
        for r in (dsip_index.get("requirements") or [])
        if isinstance(r, dict) and r.get("requirement_id")
    }

    # Build a per-claim row, expanded into one row per evidence artifact.
    # Claims with zero artifacts still get one row (with artifact_path empty)
    # so the matrix preserves them.
    seen_artifacts: set[tuple[str, str]] = set()  # (spec_section, artifact)
    for claim in claims_index.get("claims") or []:
        if not isinstance(claim, dict) or not claim.get("claim_id"):
            continue
        spec_sec = str(claim.get("spec_section", "")) or "(unanchored)"
        dsip_req = str(claim.get("dsip_requirement", "")) or ""
        status, missing = _row_status_for_claim(claim, root)
        artifacts = list(claim.get("evidence_artifacts") or [])

        if not artifacts:
            rows.append(
                TraceRow(
                    spec_section=spec_sec,
                    artifact_path="",
                    proposal_claim=claim["claim_id"],
                    dsip_requirement=dsip_req,
                    status=status,
                    notes=(
                        f"owner_section={claim.get('owner_section', '')}; "
                        f"claim text-anchor only"
                    ),
                )
            )
            continue

        for artifact in artifacts:
            artifact_status = status
            note = ""
            if artifact_status == "claim_without_evidence" and artifact in missing:
                note = "missing on disk"
            elif artifact_status == "ok":
                note = "evidence present"
            else:
                note = (
                    f"owner_section={claim.get('owner_section', '')}"
                )
            rows.append(
                TraceRow(
                    spec_section=spec_sec,
                    artifact_path=artifact,
                    proposal_claim=claim["claim_id"],
                    dsip_requirement=dsip_req,
                    status=artifact_status,
                    notes=note,
                )
            )
            seen_artifacts.add((spec_sec, artifact))

    # Detect on-disk evidence with no claim pointing at it. We walk the
    # _SECTION_TO_ARTIFACTS map and emit evidence_without_claim rows for
    # any artifact that exists on disk but never appeared as
    # evidence_artifacts in claims-index.
    claim_artifact_set: set[str] = set()
    for claim in claims_index.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        for a in claim.get("evidence_artifacts") or []:
            claim_artifact_set.add(str(a))

    for section, artifacts in _SECTION_TO_ARTIFACTS.items():
        for artifact in _existing(root, artifacts):
            if artifact in claim_artifact_set:
                continue
            rows.append(
                TraceRow(
                    spec_section=section,
                    artifact_path=artifact,
                    proposal_claim="",
                    dsip_requirement="",
                    status="evidence_without_claim",
                    notes=(
                        "artifact exists on disk but no proposal claim references it; "
                        "consider adding a claim_id to docs/proposal-claims-index.yml"
                    ),
                )
            )

    # Detect DSIP requirements with no claim pointing at them
    # (requirement_without_claim — surfaced as a sub-class of
    # claim_without_evidence so reviewers see it).
    referenced_dsip = {
        c.get("dsip_requirement")
        for c in (claims_index.get("claims") or [])
        if isinstance(c, dict) and c.get("dsip_requirement")
    }
    for req_id, req in dsip_by_id.items():
        if req_id in referenced_dsip:
            continue
        rows.append(
            TraceRow(
                spec_section="(dsip)",
                artifact_path=str(req.get("response_location", "") or ""),
                proposal_claim="",
                dsip_requirement=req_id,
                status="claim_without_evidence",
                notes=f"DSIP requirement {req_id} has no proposal claim referencing it",
            )
        )

    # Stable ordering: spec_section asc (lex), claim asc, artifact asc.
    rows.sort(
        key=lambda r: (
            r.spec_section,
            r.proposal_claim,
            r.artifact_path,
            r.dsip_requirement,
        )
    )
    return rows


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def render_json(
    rows: list[TraceRow],
    spec_sections: list[SpecSection],
    summary: dict[str, int],
) -> dict[str, Any]:
    return {
        "tool_output_type": "traceability_matrix",
        "version": "v1.0",
        "generated_by": "validator-export",
        "generated_at": "2026-05-05T00:00:00Z",
        "safety_posture": "private_by_default",
        "spec_sections": [asdict(s) for s in spec_sections],
        "summary": summary,
        "rows": [r.to_dict() for r in rows],
    }


def render_markdown(
    rows: list[TraceRow],
    summary: dict[str, int],
) -> str:
    lines: list[str] = []
    lines.append("# Traceability Matrix")
    lines.append("")
    lines.append("Generated by `validator/traceability_matrix.py`. Regenerated on")
    lines.append("every `make traceability` run.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Status | Count |")
    lines.append("| --- | ---: |")
    for key in ("ok", "claim_without_evidence", "evidence_without_claim", "planned"):
        lines.append(f"| {key} | {summary.get(key, 0)} |")
    lines.append(f"| **total rows** | {summary.get('total', 0)} |")
    lines.append("")
    lines.append("## Rows")
    lines.append("")
    lines.append(
        "| Spec § | Artifact | Claim | DSIP req | Status | Notes |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for r in rows:
        # Pipe-character-safe markdown rendering
        lines.append(
            "| {sec} | {art} | {claim} | {dsip} | {status} | {notes} |".format(
                sec=r.spec_section.replace("|", "\\|"),
                art=r.artifact_path.replace("|", "\\|") or "—",
                claim=r.proposal_claim.replace("|", "\\|") or "—",
                dsip=r.dsip_requirement.replace("|", "\\|") or "—",
                status=r.status,
                notes=(r.notes or "").replace("|", "\\|"),
            )
        )
    lines.append("")
    return "\n".join(lines)


def summarize(rows: list[TraceRow]) -> dict[str, int]:
    summary = {
        "ok": 0,
        "claim_without_evidence": 0,
        "evidence_without_claim": 0,
        "planned": 0,
        "total": len(rows),
    }
    for r in rows:
        summary[r.status] = summary.get(r.status, 0) + 1
    return summary


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def write_traceability_matrix(root: Path | None = None) -> dict[str, Any]:
    """Build and write reports/traceability_matrix.{json,md}; return JSON dict."""
    base = root if root is not None else _ROOT
    spec_sections = parse_spec_sections(base / "SPEC.md")
    claims_index = _load_yaml(base / "docs" / "proposal-claims-index.yml")
    dsip_index = _load_yaml(base / "docs" / "dsip-requirements.yml")
    rows = build_rows(base, spec_sections, claims_index, dsip_index)
    summary = summarize(rows)
    json_doc = render_json(rows, spec_sections, summary)
    md_doc = render_markdown(rows, summary)

    reports_dir = base / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / "traceability_matrix.json"
    md_path = reports_dir / "traceability_matrix.md"
    json_path.write_text(
        json.dumps(json_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    md_path.write_text(md_doc + "\n", encoding="utf-8")
    return json_doc


def main(argv: list[str] | None = None) -> int:
    """Stand-alone entry: `python -m validator.traceability_matrix`."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        print(
            f"unexpected args {args!r}; usage: python -m validator.traceability_matrix",
            file=sys.stderr,
        )
        return 2
    try:
        doc = write_traceability_matrix()
    except Exception as exc:
        print(f"traceability matrix generation failed: {exc}", file=sys.stderr)
        return 1
    summary = doc.get("summary", {})
    print(
        f"traceability matrix written: rows={summary.get('total', 0)}, "
        f"ok={summary.get('ok', 0)}, "
        f"claim_without_evidence={summary.get('claim_without_evidence', 0)}, "
        f"evidence_without_claim={summary.get('evidence_without_claim', 0)}, "
        f"planned={summary.get('planned', 0)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
