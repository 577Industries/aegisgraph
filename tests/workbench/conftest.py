"""Shared fixtures for workbench tests.

Each test that needs a synthetic on-disk record landscape calls
`fake_repo_with_records(tmp_path)` to drop a deterministic mini-repo
under tmp_path with one AG-EV-*, AG-DIS-*, AG-CRASH-*, AG-IV-*, and
AG-XSMA-* record. Records carry valid hash chains so `validate_repo`
+ the workbench scanner both succeed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aegisgraph.hashchain import attach_hash_chain


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """A minimal repo tree with one record per engine bucket.

    Returns the repo root (tmp_path). Each engine writes a JSON file at
    the on-disk location the registry scans.
    """
    _write_evidence_record(tmp_path)
    _write_disagreement_record(tmp_path)
    _write_crash_record(tmp_path)
    _write_invariant_violation_record(tmp_path)
    _write_crosssma_candidate(tmp_path)
    return tmp_path


def _write_evidence_record(root: Path) -> None:
    rec = {
        "id": "AG-EV-TEST-001",
        "version": "v1.0",
        "claim_state": "observed",
        "target": {
            "name": "Test Signal Android",
            "repo_url": "https://example.invalid/signal",
            "commit": "abc1234",
            "source_policy": "anchor-only",
        },
        "path_class": "media_decode",
        "discovery_engine": "extraction",
        "score_vector": {
            "remote_reachability": 0.5,
            "attacker_control": 0.5,
            "parser_complexity": 0.5,
            "native_boundary": 0.5,
            "auth_boundary": 0.5,
            "privilege_impact": 0.5,
            "exploit_history": 0.5,
            "mitigation_strength": 0.5,
            "observability": 0.5,
            "confidence": 0.5,
            "total": 5.0,
        },
        "nodes": [
            {
                "id": "entry.test",
                "node_type": "entry_point",
                "label": "test entry",
                "source_anchor": "test:1",
                "evidence_source": "synthetic_test",
            }
        ],
        "edges": [],
        "evidence_refs": [
            {
                "id": "REF-TEST-001",
                "tool": "synthetic-tool",
                "version": "test",
                "command": "extraction/output/test/graph.json",
                "output_hash": "a" * 64,
            }
        ],
        "recommendation_refs": [],
        "limitations": "Synthetic test record for workbench registry tests; no real-world claim.",
        "validation_task": {
            "id": "VT-TEST-001",
            "command": "true",
            "expected_output": "no output",
            "status": "planned",
        },
        "provenance": {
            "generated_by": "workbench-test",
            "generated_at": "2026-05-13T00:00:00Z",
            "source": "fake_repo fixture",
            "private_by_default": True,
        },
        "safety_flags": [],
    }
    sealed = attach_hash_chain(rec)
    _write_json(
        root / "extraction" / "output" / "test" / "graph.json",
        {"records": [sealed], "generated_at": "2026-05-13T00:00:00Z"},
    )


def _write_disagreement_record(root: Path) -> None:
    rec = {
        "disagreement_id": "AG-DIS-TEST-URL-001",
        "version": "v1.0",
        "discovery_engine": "polydiff",
        "family": "url",
        "witness_sha256": "b" * 64,
        "witness_size_bytes": 0,
        "implementations_disagreeing": ["okhttp@5.0.0", "java.net.URI@21"],
        "fact_vector_diff": {"host": ["example.test", "example.invalid"]},
        "triage_class": "MEDIUM",
        "provenance": {
            "generated_by": "workbench-test",
            "generated_at": "2026-05-13T00:00:00Z",
            "source": "fake_repo fixture",
            "private_by_default": True,
        },
    }
    sealed = attach_hash_chain(rec)
    _write_json(
        root / "polydiff" / "evidence" / "test_disagreements.json",
        {"disagreements": [sealed]},
    )


def _write_crash_record(root: Path) -> None:
    rec = {
        "crash_id": "AG-CRASH-TEST-001",
        "version": "v1.0",
        "discovery_engine": "harnessgen",
        "harness_id": "test_harness",
        "crash_sha256": "c" * 64,
        "stack_trace_hash": "d" * 64,
        "crash_class": "ArrayIndexOutOfBoundsException",
        "minimized_input_size_bytes": 16,
        "novelty": "unknown",
        "provenance": {
            "generated_by": "workbench-test",
            "generated_at": "2026-05-13T00:00:00Z",
            "source": "fake_repo fixture",
            "private_by_default": True,
        },
    }
    sealed = attach_hash_chain(rec)
    _write_json(
        root / "aegisgraph" / "harnessgen" / "runs" / "test" / "crashes.json",
        {"crashes": [sealed]},
    )


def _write_invariant_violation_record(root: Path) -> None:
    rec = {
        "violation_id": "AG-IV-TEST-001",
        "version": "v1.0",
        "discovery_engine": "invariantcheck",
        "invariant_id": "INV-07",
        "target_id": "signal_android",
        "rule_id": "test-rule",
        "rule_engine": "codeql",
        "severity": "warning",
        "location": {
            "repo_url": "https://example.invalid/signal",
            "commit": "abcd1234",
            "path": "src/test.kt",
            "start_line": 10,
        },
        "sarif_result_uri": "aegisgraph/invariants/sarif/test.sarif#result_0",
        "provenance": {
            "generated_by": "workbench-test",
            "generated_at": "2026-05-13T00:00:00Z",
            "source": "fake_repo fixture",
            "private_by_default": True,
        },
    }
    sealed = attach_hash_chain(rec)
    _write_json(
        root / "aegisgraph" / "invariants" / "output" / "violations.json",
        {"invariant_violations": [sealed]},
    )


def _write_crosssma_candidate(root: Path) -> None:
    rec = {
        "candidate_id": "AG-XSMA-TEST-001",
        "version": "v1.0",
        "discovery_engine": "crosssma",
        "source_finding_id": "AG-DIS-TEST-URL-001",
        "pattern_type": "parser_disagreement",
        "structural_signature": "e" * 64,
        "target_findings": [
            {"target": "signal_android", "status": "candidate_path"},
            {"target": "element_x_android", "status": "candidate_path"},
        ],
        "provenance": {
            "generated_by": "workbench-test",
            "generated_at": "2026-05-13T00:00:00Z",
            "source": "fake_repo fixture",
            "private_by_default": True,
        },
    }
    sealed = attach_hash_chain(rec)
    _write_json(
        root / "aegisgraph" / "crosssma" / "evidence" / "candidates.json",
        {"cross_target_candidates": [sealed]},
    )


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
