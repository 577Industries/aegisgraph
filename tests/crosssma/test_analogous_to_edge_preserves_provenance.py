"""Provenance preservation across the source-finding → cross-target edge.

Whenever a target_findings cell in an AG-XSMA-* record points back at
a source AG-DIS-* / AG-IV-* / AG-CRASH-*, the source_finding_id MUST
appear in the record top-level and the cell MUST be traceable back to
it via that id. We must not lose the audit trail.

Additionally: the `provenance.source` field must reference the source
finding so a reviewer can re-derive the matrix from primary evidence.
"""

from __future__ import annotations

from aegisgraph.crosssma.matrix_renderer import GraphThread, render_matrix
from aegisgraph.crosssma.target_registry import load_registry


def _thread() -> GraphThread:
    return GraphThread(
        thread_id="SIG-GP-001",
        source_target_id="signal-android",
        title="Remote URL to link preview",
        path_class="link_preview",
        pattern_type="parser_disagreement",
        family="url",
        axis="backslash_handling",
        implementations=("java.net.URI", "whatwg-url"),
        source_finding_id="AG-DIS-SIG-LINKPREVIEW-001",
        dependency_keys=("libwebp",),
    )


def test_source_finding_id_on_record_matches_thread() -> None:
    record = render_matrix([_thread()], load_registry())[0]
    assert record["source_finding_id"] == "AG-DIS-SIG-LINKPREVIEW-001"


def test_provenance_source_references_source_finding() -> None:
    record = render_matrix([_thread()], load_registry())[0]
    assert "AG-DIS-SIG-LINKPREVIEW-001" in record["provenance"]["source"], (
        "provenance.source must reference the source_finding_id so the "
        "matrix row is traceable to primary evidence"
    )


def test_source_target_cell_carries_back_pointer() -> None:
    """The cell for the source target must carry an evidence_note (or
    similar) pointing back to the original finding id."""
    record = render_matrix([_thread()], load_registry())[0]
    source_cell = [
        c for c in record["target_findings"]
        if c["target"] == "signal-android"
    ][0]
    note = source_cell.get("evidence_note") or ""
    fid = source_cell.get("finding_id") or ""
    assert "AG-DIS-SIG-LINKPREVIEW-001" in (note + fid), (
        f"source cell should reference source finding; cell={source_cell}"
    )


def test_provenance_generated_by_namespaced_to_crosssma() -> None:
    record = render_matrix([_thread()], load_registry())[0]
    assert "crosssma" in record["provenance"]["generated_by"].lower(), (
        f"provenance.generated_by should namespace to crosssma; got "
        f"{record['provenance']['generated_by']!r}"
    )


def test_provenance_private_by_default_true() -> None:
    record = render_matrix([_thread()], load_registry())[0]
    assert record["provenance"]["private_by_default"] is True
