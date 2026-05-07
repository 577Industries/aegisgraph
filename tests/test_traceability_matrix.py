"""Traceability matrix tests.

Verifies that:
  - Every active claim in docs/proposal-claims-index.yml shows up as
    at least one row in the traceability matrix.
  - The matrix surfaces missing artifacts as `claim_without_evidence`.
  - SPEC.md sections are extracted (non-empty list).
  - The traceability subcommand writes both reports/traceability_matrix.json
    and reports/traceability_matrix.md.
  - Empty/garbage SPEC.md is handled gracefully.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from validator.traceability_matrix import (
    build_rows,
    parse_spec_sections,
    summarize,
    write_traceability_matrix,
)


REPO = Path(__file__).resolve().parents[1]


def test_spec_sections_extracted_from_repo() -> None:
    sections = parse_spec_sections(REPO / "SPEC.md")
    assert len(sections) > 10
    section_numbers = {s.section for s in sections}
    # Sanity: top-level sections from SPEC.md should be present
    assert "1" in section_numbers
    assert "8" in section_numbers


def test_spec_sections_missing_file_returns_empty(tmp_path: Path) -> None:
    sections = parse_spec_sections(tmp_path / "no-spec.md")
    assert sections == []


def _load_claims_yaml() -> dict:
    with (REPO / "docs" / "proposal-claims-index.yml").open(
        "r", encoding="utf-8"
    ) as handle:
        return yaml.safe_load(handle) or {}


def _load_dsip_yaml() -> dict:
    with (REPO / "docs" / "dsip-requirements.yml").open(
        "r", encoding="utf-8"
    ) as handle:
        return yaml.safe_load(handle) or {}


def test_every_active_claim_has_at_least_one_row() -> None:
    claims = _load_claims_yaml()
    dsip = _load_dsip_yaml()
    spec_sections = parse_spec_sections(REPO / "SPEC.md")
    rows = build_rows(REPO, spec_sections, claims, dsip)

    active_claim_ids = {
        c["claim_id"]
        for c in (claims.get("claims") or [])
        if isinstance(c, dict)
        and c.get("claim_id")
        and c.get("status") != "retired"
    }
    referenced = {r.proposal_claim for r in rows if r.proposal_claim}
    missing = active_claim_ids - referenced
    assert not missing, f"claims missing from matrix: {sorted(missing)}"


def test_summary_counts_match_row_statuses() -> None:
    claims = _load_claims_yaml()
    dsip = _load_dsip_yaml()
    spec_sections = parse_spec_sections(REPO / "SPEC.md")
    rows = build_rows(REPO, spec_sections, claims, dsip)
    summary = summarize(rows)
    assert summary["total"] == len(rows)
    assert summary["total"] == sum(
        summary[k] for k in ("ok", "claim_without_evidence", "evidence_without_claim", "planned")
    )


def test_traceability_writes_both_files(tmp_path: Path) -> None:
    """write_traceability_matrix(root) writes JSON + Markdown into
    <root>/reports/."""
    # Build a synthetic root with the schema dir + the YAMLs the
    # traceability module reads. We don't need on-disk evidence for the
    # smoke test — missing artifacts simply surface as
    # claim_without_evidence rows, which is fine.
    target = tmp_path / "synthetic-repo"
    target.mkdir()
    shutil.copytree(REPO / "schema", target / "schema")
    shutil.copytree(REPO / "docs", target / "docs")
    shutil.copy(REPO / "SPEC.md", target / "SPEC.md")
    (target / "reports").mkdir()

    doc = write_traceability_matrix(target)
    assert (target / "reports" / "traceability_matrix.json").exists()
    assert (target / "reports" / "traceability_matrix.md").exists()
    assert doc["summary"]["total"] >= 1
    assert doc["tool_output_type"] == "traceability_matrix"


def test_traceability_matrix_json_is_valid(tmp_path: Path) -> None:
    """Generated JSON parses and contains the expected top-level keys."""
    target = tmp_path / "synthetic-repo"
    target.mkdir()
    shutil.copytree(REPO / "schema", target / "schema")
    shutil.copytree(REPO / "docs", target / "docs")
    shutil.copy(REPO / "SPEC.md", target / "SPEC.md")
    write_traceability_matrix(target)

    text = (target / "reports" / "traceability_matrix.json").read_text()
    doc = json.loads(text)
    assert doc.get("tool_output_type") == "traceability_matrix"
    assert isinstance(doc.get("rows"), list)
    assert isinstance(doc.get("spec_sections"), list)
    assert isinstance(doc.get("summary"), dict)


def test_missing_artifact_surfaces_claim_without_evidence(tmp_path: Path) -> None:
    """A claim that lists an artifact path that doesn't exist on disk
    must show as claim_without_evidence."""
    target = tmp_path / "synthetic-repo"
    target.mkdir()
    shutil.copytree(REPO / "schema", target / "schema")
    (target / "docs").mkdir()
    (target / "SPEC.md").write_text("## 1 First\n## 2 Second\n", encoding="utf-8")
    # Synthetic claims doc with one artifact that doesn't exist
    (target / "docs" / "proposal-claims-index.yml").write_text(
        """
claims:
  - claim_id: AG-CLAIM-TEST-001
    source_location: "test"
    claim_text: "test"
    owner_section: technical_volume
    spec_section: "1"
    evidence_artifacts:
      - missing/file/that/does/not/exist.json
    status: drafted
""",
        encoding="utf-8",
    )
    (target / "docs" / "dsip-requirements.yml").write_text(
        "requirements: []\nksa_crosswalk: {}\ndeliverables: []\n",
        encoding="utf-8",
    )

    doc = write_traceability_matrix(target)
    assert doc["summary"]["claim_without_evidence"] >= 1
    rows_for_claim = [
        r for r in doc["rows"] if r["proposal_claim"] == "AG-CLAIM-TEST-001"
    ]
    assert len(rows_for_claim) == 1
    assert rows_for_claim[0]["status"] == "claim_without_evidence"
    assert "missing on disk" in rows_for_claim[0]["notes"]


def test_evidence_without_claim_is_surfaced(tmp_path: Path) -> None:
    """If validation-report.json exists on disk but no claim references
    it, the row should appear with status=evidence_without_claim."""
    target = tmp_path / "synthetic-repo"
    target.mkdir()
    shutil.copytree(REPO / "schema", target / "schema")
    (target / "docs").mkdir()
    (target / "SPEC.md").write_text("## 1 First\n", encoding="utf-8")
    # Empty claims index: nothing claims validation-report.json
    (target / "docs" / "proposal-claims-index.yml").write_text(
        "claims: []\n", encoding="utf-8"
    )
    (target / "docs" / "dsip-requirements.yml").write_text(
        "requirements: []\nksa_crosswalk: {}\ndeliverables: []\n",
        encoding="utf-8",
    )
    # Drop a stub validation-report.json — that file is in
    # _SECTION_TO_ARTIFACTS for spec section "10"
    (target / "validation-report.json").write_text("{}", encoding="utf-8")

    doc = write_traceability_matrix(target)
    statuses = {r["status"] for r in doc["rows"]}
    assert "evidence_without_claim" in statuses
