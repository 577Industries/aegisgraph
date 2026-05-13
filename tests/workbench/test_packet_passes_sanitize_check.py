"""validator.sanitize_check.scan_export_tree must report ok=True on the packet.

The packet is *the* reviewer hand-off; if sanitize-check fires any
blocking rule against the emitted findings/ tree, the packet is
unsafe. This test enforces the integration contract.
"""

from __future__ import annotations

from pathlib import Path

from aegisgraph.workbench.packet_export import export_packet
from validator.sanitize_check import scan_export_tree


def test_packet_findings_tree_passes_sanitize_check(fake_repo: Path) -> None:
    out_dir = fake_repo / "exports" / "reviewer-packet"
    manifest = export_packet(fake_repo, top_n=10, out_dir=out_dir)
    assert manifest["sanitize_check"]["status"] == "pass", manifest["sanitize_check"]
    iso = manifest["iso_date"]
    findings_tree = out_dir / iso / "findings"
    report = scan_export_tree(findings_tree)
    assert report.ok, "\n".join(f.to_line() for f in report.failures)


def test_packet_sanitize_check_reports_failures_when_record_carries_blocked_field(
    fake_repo: Path,
) -> None:
    """If a blocked field slips through, the manifest must report sanitize_check.status='fail'.

    We deliberately add a record carrying `nmap` and `password=test` (live-
    target-probing + credentialed-interaction patterns) to the source
    tree. The packet's public projection only strips PAYLOAD field names
    — pattern-based safety violations are NOT stripped, so the
    sanitize-check must catch them.
    """
    import json as _json
    from aegisgraph.hashchain import attach_hash_chain

    bad_rec = {
        "id": "AG-EV-BAD-001",
        "version": "v1.0",
        "claim_state": "observed",
        "target": {
            "name": "Synthetic",
            "repo_url": "https://example.invalid/x",
            "commit": "abcd",
            "source_policy": "anchor-only",
        },
        "path_class": "media_decode",
        "discovery_engine": "extraction",
        "score_vector": {
            "remote_reachability": 0,
            "attacker_control": 0,
            "parser_complexity": 0,
            "native_boundary": 0,
            "auth_boundary": 0,
            "privilege_impact": 0,
            "exploit_history": 0,
            "mitigation_strength": 0,
            "observability": 0,
            "confidence": 0,
            "total": 9.9,  # ensure top-N picks it up
        },
        "nodes": [
            {
                "id": "node.bad",
                "node_type": "entry_point",
                "label": "bad",
                "source_anchor": "x",
                "evidence_source": "synthetic_test",
            }
        ],
        "edges": [],
        "evidence_refs": [],
        "recommendation_refs": [],
        "limitations": "Contains live-target-probing markers nmap to exercise sanitize-check fail path.",
        "validation_task": {
            "id": "VT-BAD",
            "command": "true",
            "expected_output": "no output",
            "status": "planned",
        },
        "provenance": {
            "generated_by": "test",
            "generated_at": "2026-05-13T00:00:00Z",
            "source": "intentionally bad: nmap masscan password=test",
            "private_by_default": True,
        },
        "safety_flags": [],
    }
    sealed = attach_hash_chain(bad_rec)
    path = fake_repo / "extraction" / "output" / "bad" / "graph.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _json.dumps({"records": [sealed]}, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    out_dir = fake_repo / "exports" / "reviewer-packet"
    manifest = export_packet(fake_repo, top_n=10, out_dir=out_dir)
    assert manifest["sanitize_check"]["status"] == "fail", manifest["sanitize_check"]
    assert manifest["sanitize_check"]["failures"], "expected at least one failure entry"
