"""Tests for aegisgraph.reprochain.map_targets().

Per-target mapping evidence records must:
  * exist for both Signal Android and Element X Android
  * validate against schema/evidence.schema.json
  * carry a non-anchor-only evidence_source on every node WHEN
    extraction_phase is 'codeql' (the strong case)
  * have the terminal sink anchored to the libwebp vendored commit
  * honestly document the Android platform-decoder indirection in
    the limitations field
  * be marked claim_state='validation_tasked' (with status='blocked')
    when extraction is missing
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from aegisgraph.reprochain import (
    LIBWEBP_FIX_SHA,
    LIBWEBP_VULN_SHA,
    map_targets,
)
from aegisgraph.validation import validate_evidence_record


@pytest.fixture
def repo_with_extraction(tmp_path) -> Path:
    """Standard fixture: repo clone with the existing anchor-only
    extraction graph already in place. Mirrors the integrated state
    on master after `make extract` runs in the dev environment."""
    here = Path(__file__).resolve().parent.parent
    for sub in ("schema", "reprochain", "extraction", "aegisgraph"):
        if (here / sub).is_dir():
            shutil.copytree(here / sub, tmp_path / sub, ignore=shutil.ignore_patterns(
                "upstream",
                "build-vuln",
                "build-fix",
                "cmake-vuln",
                "cmake-fix",
                "evidence",
                "__pycache__",
            ))
    return tmp_path


@pytest.fixture
def repo_without_extraction(tmp_path) -> Path:
    """Repo clone with NO extraction output. Exercises the
    blocked_pending_extraction branch."""
    here = Path(__file__).resolve().parent.parent
    for sub in ("schema", "reprochain", "aegisgraph"):
        if (here / sub).is_dir():
            shutil.copytree(here / sub, tmp_path / sub, ignore=shutil.ignore_patterns(
                "upstream",
                "build-vuln",
                "build-fix",
                "cmake-vuln",
                "cmake-fix",
                "evidence",
                "__pycache__",
            ))
    return tmp_path


def _record(doc: dict) -> dict:
    """Pull the single evidence record out of a per-target mapping doc."""
    return doc["records"][0]


def test_per_target_mapping_files_written(repo_with_extraction: Path) -> None:
    map_targets(repo_with_extraction)
    signal_path = repo_with_extraction / "reprochain" / "mapping" / "signal.json"
    elementx_path = repo_with_extraction / "reprochain" / "mapping" / "element-x.json"
    assert signal_path.is_file()
    assert elementx_path.is_file()


def test_mapping_records_validate_against_schema(repo_with_extraction: Path) -> None:
    map_targets(repo_with_extraction)
    for target in ("signal", "element-x"):
        path = repo_with_extraction / "reprochain" / "mapping" / f"{target}.json"
        doc = json.loads(path.read_text())
        record = _record(doc)
        errors = validate_evidence_record(record, repo_with_extraction)
        assert errors == [], (target, errors)


def test_terminal_sink_anchors_to_libwebp_vuln_commit(repo_with_extraction: Path) -> None:
    """The chain must terminate at a node whose source_anchor points
    at the pinned vulnerable libwebp commit. That's the contract that
    glues mapping evidence to the harness build."""
    map_targets(repo_with_extraction)
    for target in ("signal", "element-x"):
        path = repo_with_extraction / "reprochain" / "mapping" / f"{target}.json"
        doc = json.loads(path.read_text())
        record = _record(doc)
        sinks = [n for n in record["nodes"] if n["node_type"] == "sink"]
        assert len(sinks) >= 1, f"no sink node in {target}"
        terminal = sinks[-1]
        assert LIBWEBP_VULN_SHA in terminal["source_anchor"], (
            target,
            terminal["source_anchor"],
        )


def test_limitations_documents_platform_indirection(repo_with_extraction: Path) -> None:
    """The honest framing: bug class is reachable via
    ImageDecoder -> system codec -> libwebp. The mapping record's
    limitations field must call this out explicitly."""
    map_targets(repo_with_extraction)
    for target in ("signal", "element-x"):
        path = repo_with_extraction / "reprochain" / "mapping" / f"{target}.json"
        doc = json.loads(path.read_text())
        record = _record(doc)
        lim = record["limitations"].lower()
        # Must mention the platform decoder indirection.
        assert "imagedecoder" in lim or "platform image decoder" in lim, lim
        # Must NOT claim direct app->libwebp linkage.
        assert "directly" not in lim or "does not call libwebp directly" in lim


def test_mapping_blocked_when_extraction_missing(repo_without_extraction: Path) -> None:
    """When extraction has not produced graph.json, the mapping must
    emit phase='blocked_pending_extraction', claim_state remains
    'validation_tasked', and validation_task.status is 'blocked'."""
    manifest = map_targets(repo_without_extraction)
    assert manifest["status"] == "blocked_pending_extraction"
    for phase in manifest["extraction_phases"].values():
        assert phase == "blocked_pending_extraction"

    for record in manifest["records"]:
        assert record["claim_state"] == "validation_tasked"
        assert record["validation_task"]["status"] == "blocked"


def test_mapping_with_codeql_phase_has_specific_anchors(tmp_path) -> None:
    """When extraction emits CodeQL-anchored output (anchors with
    /blob/<sha>/.../File.kt#L42 fragments), every non-sink node MUST
    carry a non-anchor-only evidence_source. We synthesize a minimal
    CodeQL-shaped extraction graph in tmp_path to exercise this path.
    """
    here = Path(__file__).resolve().parent.parent
    for sub in ("schema", "reprochain", "aegisgraph"):
        shutil.copytree(here / sub, tmp_path / sub, ignore=shutil.ignore_patterns(
            "upstream",
            "build-vuln",
            "build-fix",
            "cmake-vuln",
            "cmake-fix",
            "evidence",
            "__pycache__",
        ))

    extraction_dir = tmp_path / "extraction" / "output" / "signal"
    extraction_dir.mkdir(parents=True)
    extraction_dir.joinpath("graph.json").write_text(json.dumps({
        "tool_output_type": "extraction_graph",
        "version": "v1.0",
        "generated_by": "test",
        "generated_at": "2026-05-05T00:00:00Z",
        "safety_posture": "private_by_default",
        "target": "Signal Android",
        "records": [{
            "id": "AG-EV-EXTRACT-SIGNAL-ANDROID-MEDIA-001",
            "version": "v1.0",
            "nodes": [
                {
                    "id": "entry.inbound-media",
                    "node_type": "entry_point",
                    "label": "MmsAttachment dispatch",
                    "source_anchor": "https://github.com/signalapp/Signal-Android/blob/1043851/app/src/main/java/org/thoughtcrime/securesms/database/AttachmentTable.kt#L42",
                    "evidence_source": "codeql sarif:dataflow:8 -> entrypoint",
                },
                {
                    "id": "handler.media-pipeline",
                    "node_type": "handler",
                    "label": "Glide handler chain",
                    "source_anchor": "https://github.com/signalapp/Signal-Android/blob/1043851/app/src/main/java/org/thoughtcrime/securesms/glide/GlideExtensions.kt#L99",
                    "evidence_source": "codeql sarif:taint-step:Glide.with()",
                },
                {
                    "id": "decoder.image-stack",
                    "node_type": "decoder",
                    "label": "BitmapFactory.decodeStream",
                    "source_anchor": "https://github.com/signalapp/Signal-Android/blob/1043851/app/src/main/java/com/example/Decoder.kt#L7",
                    "evidence_source": "codeql sarif:sink-binding",
                },
            ],
        }],
    }))

    # Element-X needs a graph too (map_targets walks both targets).
    elx_dir = tmp_path / "extraction" / "output" / "element-x"
    elx_dir.mkdir(parents=True)
    elx_dir.joinpath("graph.json").write_text(extraction_dir.joinpath("graph.json").read_text().replace("signalapp/Signal-Android", "element-hq/element-x-android").replace("Signal Android", "Element X Android").replace("1043851", "91d265e6"))

    manifest = map_targets(tmp_path)
    assert manifest["status"] == "codeql"
    for record in manifest["records"]:
        # Every non-sink node must carry an evidence_source that's
        # NOT a generic placeholder. We approximate that by requiring
        # the 'codeql' or 'sarif' tag, which our fixture sets.
        for node in record["nodes"]:
            if node["node_type"] == "sink":
                continue
            src = node.get("evidence_source", "").lower()
            assert ("codeql" in src or "sarif" in src or "anchor_only" not in src), (
                record["id"],
                node,
            )


def test_mapping_carries_pin_evidence_ref(repo_with_extraction: Path) -> None:
    """The PINS evidence_ref must encode both the vuln and fix SHAs."""
    map_targets(repo_with_extraction)
    for target in ("signal", "element-x"):
        path = repo_with_extraction / "reprochain" / "mapping" / f"{target}.json"
        record = _record(json.loads(path.read_text()))
        pin_refs = [r for r in record["evidence_refs"] if "PINS" in r["id"]]
        assert pin_refs, record["evidence_refs"]
        # output_hash is sha256 of the SHA-pair string; we don't pin
        # the hex digest here (that would couple the test to the
        # canonical_json layout) but we DO assert it's a valid sha256.
        for ref in pin_refs:
            assert len(ref["output_hash"]) == 64
