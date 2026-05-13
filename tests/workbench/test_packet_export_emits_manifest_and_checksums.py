"""packet_export emits manifest.json + checksums + per-finding files."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from aegisgraph.workbench.filters import FilterSpec
from aegisgraph.workbench.packet_export import export_packet


def test_packet_emits_expected_tree(fake_repo: Path) -> None:
    out_dir = fake_repo / "exports" / "reviewer-packet"
    manifest = export_packet(fake_repo, top_n=10, out_dir=out_dir)
    iso = manifest["iso_date"]
    target = out_dir / iso

    assert (target / "manifest.json").is_file()
    assert (target / "bundle.md").is_file()
    assert (target / "checksums.sha256").is_file()
    assert (target / "findings").is_dir()

    # Every emitted finding has both JSON and Markdown.
    for f in manifest["findings"]:
        assert (target / f["json_path"]).is_file()
        assert (target / f["evidence_path"]).is_file()


def test_packet_manifest_schema_has_required_fields(fake_repo: Path) -> None:
    out_dir = fake_repo / "exports" / "reviewer-packet"
    manifest = export_packet(fake_repo, top_n=10, out_dir=out_dir)
    for required in (
        "tool_output_type",
        "version",
        "generated_by",
        "generated_at",
        "safety_posture",
        "iso_date",
        "top_n",
        "filters",
        "findings",
        "artifacts",
        "checksums_file",
        "sanitize_check",
    ):
        assert required in manifest, f"manifest missing {required}"
    assert manifest["tool_output_type"] == "reviewer_packet"
    assert manifest["safety_posture"] == "sanitized_candidate"


def test_packet_checksums_file_matches_artifact_hashes(fake_repo: Path) -> None:
    out_dir = fake_repo / "exports" / "reviewer-packet"
    manifest = export_packet(fake_repo, top_n=10, out_dir=out_dir)
    target = out_dir / manifest["iso_date"]
    checksums_path = target / "checksums.sha256"
    checksum_lines = checksums_path.read_text(encoding="utf-8").strip().splitlines()
    parsed = {}
    for line in checksum_lines:
        parts = line.split("  ", 1)
        assert len(parts) == 2, f"malformed checksum line: {line!r}"
        sha, rel = parts
        parsed[rel] = sha
    # Every per-finding file recorded in artifacts must appear in checksums.
    for art in manifest["artifacts"]:
        rel = art["path"]
        if rel == "manifest.json":
            # The manifest itself is rehashed AFTER artifacts are listed;
            # checksums.sha256 carries the post-final manifest hash.
            assert rel in parsed
            continue
        assert parsed.get(rel) == art["sha256"], f"sha mismatch for {rel}"


def test_packet_filter_expression_narrows_top_n(fake_repo: Path) -> None:
    out_dir = fake_repo / "exports" / "reviewer-packet"
    manifest = export_packet(
        fake_repo,
        top_n=10,
        out_dir=out_dir,
        filter_spec=FilterSpec.parse("engine=polydiff"),
    )
    ids = [f["record_id"] for f in manifest["findings"]]
    assert ids == ["AG-DIS-TEST-URL-001"]


def test_packet_writes_no_blocked_fields_in_findings(fake_repo: Path) -> None:
    """The public projection strips known blocked fields (defense-in-depth)."""
    # Inject a blocked field into an existing record on disk, re-run packet,
    # and verify the per-finding JSON omits the blocked field.
    extract_path = fake_repo / "extraction" / "output" / "test" / "graph.json"
    doc = json.loads(extract_path.read_text(encoding="utf-8"))
    # Append a `payload` field; the record_hash will be invalid post-injection
    # but the projection should still strip it.
    doc["records"][0]["payload"] = "should not appear in packet"
    extract_path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")

    out_dir = fake_repo / "exports" / "reviewer-packet"
    manifest = export_packet(fake_repo, top_n=10, out_dir=out_dir)
    target = out_dir / manifest["iso_date"]
    fjson = target / "findings" / "AG-EV-TEST-001.json"
    assert fjson.is_file()
    public = json.loads(fjson.read_text(encoding="utf-8"))
    assert "payload" not in public
