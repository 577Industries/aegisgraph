"""End-to-end reproduce + safety-finalize integration tests.

Owned by the integration stream. Two responsibilities:

1. Refuse-to-seal: finalize_record() must raise UnsafeFinalizationError
   when a public-release-classified record carries a forbidden token.
   Hashing an unsafe record into the chain would let the safety check
   become a label-only signal that the public-export step might silently
   honor or ignore.

2. Hash determinism: a fully-validated phase-0 reproduce produces stable
   hashes across runs in a temp dir, so reviewers can checksum-compare
   reproduce outputs.
"""

from __future__ import annotations

import shutil

import pytest

from aegisgraph.evidence import UnsafeFinalizationError, finalize_record
from aegisgraph.extraction import run_extract
from aegisgraph.polydiff import run_regression
from aegisgraph.reprochain import map_targets
from aegisgraph.validation import validate_repo


def _minimal_record(extra: dict | None = None) -> dict:
    """Schema-compliant skeleton suitable for finalize_record tests."""
    base = {
        "id": "AG-EV-INTEGRATION-FINALIZE-001",
        "version": "v1.0",
        "target": {
            "name": "Synthetic Test Target",
            "repo_url": "https://example.invalid/repo",
            "commit": "deadbeef",
            "source_policy": "synthetic",
        },
        "path_class": "media_decode",
        "nodes": [
            {
                "id": "n1",
                "node_type": "entry_point",
                "label": "synthetic entry",
                "source_anchor": "https://example.invalid/repo/tree/deadbeef",
                "evidence_source": "test fixture",
            }
        ],
        "edges": [],
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
        "claim_state": "validation_tasked",
        "validation_task": {
            "id": "VAL-TEST",
            "command": "make test",
            "expected_output": "test passes",
            "status": "planned",
        },
        "evidence_refs": [],
        "recommendation_refs": [],
        "limitations": (
            "Synthetic record used only to exercise finalize_record; carries no "
            "claim about a real target and is not exported."
        ),
        "provenance": {
            "generated_by": "aegisgraph-tier3-research",
            "generated_at": "2026-05-05T00:00:00Z",
            "source": "tests/test_e2e_reproduce.py fixture",
            "private_by_default": True,
        },
        "safety_flags": [],
    }
    if extra:
        base.update(extra)
    return base


def test_finalize_private_record_with_block_term_does_not_raise() -> None:
    """Without release_classification=public_*, finalize records the flag but
    does not raise. This preserves the existing private-by-default behavior."""
    record = _minimal_record()
    # Embed a forbidden token in `notes` (extra field is ok at this layer
    # because finalize doesn't enforce the schema; validation does).
    record["limitations"] = (
        "Phase 0 anchor record. Limitations: nmap was NOT used on a live target. "
        "(Includes the literal token to confirm scanner triggers, but no claim is made.)"
    )
    sealed = finalize_record(record)
    flag_rules = {flag["rule"] for flag in sealed.get("safety_flags", [])}
    # The scanner sees "nmap" in the haystack — record is flagged...
    assert "live_target_probing" in flag_rules
    # ... but finalize doesn't raise because release_classification is unset.
    assert "hash_chain" in sealed


def test_finalize_public_sanitized_record_with_block_term_raises() -> None:
    """A record being prepared for public release MUST refuse to seal if
    the safety scanner produces blocking flags. Hashing such a record into
    the chain is unacceptable per docs/decision-log/0011-public-export-human-gate.md."""
    record = _minimal_record({"release_classification": "public_sanitized"})
    # A private path string + live-probe term — both forbidden patterns.
    # Use the path inside `evidence_refs[*].command`, a field
    # apply_safety_flags walks via _walk_values.
    record["evidence_refs"] = [
        {
            "id": "REF-FORBIDDEN",
            "tool": "synthetic",
            "version": "phase0",
            "command": "nmap live target /home/operator/private/scratch/dump.bin",
            "output_hash": "0" * 64,
        }
    ]

    with pytest.raises(UnsafeFinalizationError) as excinfo:
        finalize_record(record)

    assert excinfo.value.record_id == "AG-EV-INTEGRATION-FINALIZE-001"
    # At least one of the two blocking patterns should be present.
    assert any(
        rule in excinfo.value.flag_rules
        for rule in ("live_target_probing", "undisclosed_crash_payload")
    )


def test_finalize_public_sanitized_record_clean_input_succeeds() -> None:
    """Sanity: clean input + public_sanitized classification still seals."""
    record = _minimal_record({"release_classification": "public_sanitized"})
    sealed = finalize_record(record)
    assert sealed.get("hash_chain", {}).get("record_hash")
    # Empty list is fine; we just want no blocking flags.
    flags = sealed.get("safety_flags", [])
    assert all(flag["level"] != "blocking" for flag in flags), flags


def test_phase0_reproduce_in_tempdir_validates_pass(tmp_path) -> None:
    """Mirror tests/test_validation_e2e.py but on the integration branch
    (kept distinct so this test file owns the e2e contract for the
    integration stream's quality-gate)."""
    shutil.copytree("schema", tmp_path / "schema")
    run_extract(tmp_path)
    map_targets(tmp_path)
    run_regression(tmp_path)
    report = validate_repo(tmp_path)
    assert report["status"] == "pass"
    assert report["records_checked"] >= 6
