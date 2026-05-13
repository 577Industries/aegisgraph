"""v0.4 sanitize-check rule extensions (T-M4.2).

Tests for plan §10 additions:

  BLOCKING_PATTERNS:
    - vendor_contact_in_public_artifact
    - disclosure_embargoed_leak
    - raw_stack_trace
    - target_source_snippet
    - crosssma_target_redistribution

  Rules:
    - Rule 7: disclosure ledger redaction (public event_type whitelist,
              vendor_contact must be org-id-only, notes_hash must be null)
    - Rule 8: SARIF source snippets (location to repo_url + commit + path +
              start_line only; no source_snippet)
    - Rule 9: crash record completeness (crash_sha256 required;
              no payload-bearing fields)

Each new BLOCKING_PATTERN has a positive (violating record produces flag)
and negative (clean record passes) test. Each new sanitize rule has a
positive and negative test using a synthetic public-export tree.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from aegisgraph.safety import blocking_flags, scan_record
from validator.sanitize_check import scan_export_tree


FIXTURES = Path(__file__).resolve().parent / "fixtures"
CLEAN = FIXTURES / "clean-export"


# ---------------------------------------------------------------------------
# BLOCKING_PATTERNS — positive tests (violating record flagged)
# ---------------------------------------------------------------------------


def test_vendor_contact_email_signal_blocks() -> None:
    """vendor_contact email at signal.org domain produces blocking flag."""
    flags = scan_record(
        {
            "safety_posture": "sanitized_candidate",
            "notes": "Contact for v0.4 disclosure: signal-security@signal.org",
            "limitations": "Anchor-only research; no live interaction.",
        }
    )
    rules = {f.rule for f in blocking_flags(flags)}
    assert "vendor_contact_in_public_artifact" in rules, rules


def test_vendor_contact_email_element_blocks() -> None:
    flags = scan_record({"contact": "security@element.io"})
    rules = {f.rule for f in blocking_flags(flags)}
    assert "vendor_contact_in_public_artifact" in rules


def test_vendor_contact_email_matrix_blocks() -> None:
    flags = scan_record({"vendor_contact": "security@matrix.org"})
    rules = {f.rule for f in blocking_flags(flags)}
    assert "vendor_contact_in_public_artifact" in rules


def test_vendor_contact_email_chromium_blocks() -> None:
    flags = scan_record({"contact": "security@chromium.org"})
    rules = {f.rule for f in blocking_flags(flags)}
    assert "vendor_contact_in_public_artifact" in rules


def test_vendor_contact_email_generic_regex_blocks() -> None:
    """Generic vendor email regex catches aomedia and wire."""
    flags = scan_record({"contact": "team-security@aomedia.org"})
    rules = {f.rule for f in blocking_flags(flags)}
    assert "vendor_contact_in_public_artifact" in rules
    flags = scan_record({"contact": "ops@wire.com"})
    rules = {f.rule for f in blocking_flags(flags)}
    assert "vendor_contact_in_public_artifact" in rules


def test_disclosure_embargoed_leak_blocks_when_public_posture() -> None:
    """reviewed_embargoed claim_state in a sanitized_candidate record blocks."""
    flags = scan_record(
        {
            "safety_posture": "sanitized_candidate",
            "claim_state": "reviewed_embargoed",
            "limitations": "Anchor-only finding scheduled for vendor coordination.",
        }
    )
    rules = {f.rule for f in blocking_flags(flags)}
    assert "disclosure_embargoed_leak" in rules


def test_raw_stack_trace_java_frame_blocks() -> None:
    """Java stack-frame regex with line numbers is blocked."""
    flags = scan_record(
        {
            "trace": "at com.example.Parse.parse(Parse.java:142)",
            "limitations": "anchor-only research record",
        }
    )
    rules = {f.rule for f in blocking_flags(flags)}
    assert "raw_stack_trace" in rules


def test_raw_stack_trace_native_frame_blocks() -> None:
    """Native (cc/cpp) frame with line number is blocked."""
    flags = scan_record(
        {
            "trace": "at libwebp::decode(decode.cc:99)",
            "limitations": "anchor-only research record",
        }
    )
    rules = {f.rule for f in blocking_flags(flags)}
    assert "raw_stack_trace" in rules


def test_target_source_snippet_long_field_blocks() -> None:
    """source_snippet field longer than 256 chars is blocked."""
    snippet = "int x = 0;\n" * 30  # well over 256 chars
    flags = scan_record(
        {
            "source_snippet": snippet,
            "limitations": "anchor-only research record",
        }
    )
    rules = {f.rule for f in blocking_flags(flags)}
    assert "target_source_snippet" in rules


def test_crosssma_target_redistribution_long_payload_blocks() -> None:
    """structural_description >128 chars containing a URL/payload in
    a cross_target_candidate record is blocked."""
    payload = (
        "https://attacker.example.com/path/with/a/very/very/very/long/url/"
        "carrying-attack-payload-bytes-here-that-cannot-be-redistributed-publicly-must-be-witness-hash-only"
    )
    assert len(payload) > 128
    flags = scan_record(
        {
            "candidate_id": "AG-XSMA-TEST-001",
            "structural_description": payload,
            "limitations": "anchor-only research record",
        }
    )
    rules = {f.rule for f in blocking_flags(flags)}
    assert "crosssma_target_redistribution" in rules


# ---------------------------------------------------------------------------
# BLOCKING_PATTERNS — negative tests (clean records pass)
# ---------------------------------------------------------------------------


def test_clean_vendor_section_passes() -> None:
    """No email address present — vendor_contact_in_public_artifact does
    not trip."""
    flags = scan_record(
        {
            "vendor_contact": "signal_org",  # org id only, no @
            "limitations": "anchor-only research record",
        }
    )
    rules = {f.rule for f in blocking_flags(flags)}
    assert "vendor_contact_in_public_artifact" not in rules


def test_disclosure_embargoed_in_private_passes() -> None:
    """reviewed_embargoed without public posture is not flagged by the
    embargoed-leak rule."""
    flags = scan_record(
        {
            "safety_posture": "private_by_default",
            "claim_state": "reviewed_embargoed",
            "limitations": "anchor-only finding awaiting vendor contact",
        }
    )
    rules = {f.rule for f in blocking_flags(flags)}
    assert "disclosure_embargoed_leak" not in rules


def test_stack_trace_hash_passes() -> None:
    """stack_trace_hash (the allowed hash-only projection) does NOT trip
    raw_stack_trace."""
    flags = scan_record(
        {
            "stack_trace_hash": "a" * 64,
            "stack_trace_summary": "ArrayIndexOutOfBoundsException at top frame",
            "limitations": "anchor-only research record",
        }
    )
    rules = {f.rule for f in blocking_flags(flags)}
    assert "raw_stack_trace" not in rules


def test_short_source_snippet_passes() -> None:
    """source_snippet shorter than 256 chars passes."""
    flags = scan_record(
        {
            "source_snippet": "int x = 0;",
            "limitations": "anchor-only research record",
        }
    )
    rules = {f.rule for f in blocking_flags(flags)}
    assert "target_source_snippet" not in rules


def test_crosssma_short_structural_description_passes() -> None:
    """structural_description under 128 chars (witness-hash form) is fine."""
    flags = scan_record(
        {
            "candidate_id": "AG-XSMA-TEST-002",
            "structural_signature": "f" * 64,
            "structural_description": "linkpreview parser disagreement family",
            "limitations": "anchor-only research record",
        }
    )
    rules = {f.rule for f in blocking_flags(flags)}
    assert "crosssma_target_redistribution" not in rules


# ---------------------------------------------------------------------------
# Rule 7 — disclosure ledger redaction
# ---------------------------------------------------------------------------


def _build_disclosure_doc(event: dict) -> dict:
    """Wrap a disclosure_event record in a public sanitized doc envelope."""
    return {
        "version": "v1.0",
        "tool_output_type": "public_sanitized_export",
        "safety_posture": "sanitized_candidate",
        "records": [event],
    }


def _disclosure_event(
    *,
    event_type: str,
    vendor_contact: str | None,
    notes_hash: str | None,
) -> dict:
    return {
        "entry_id": "AG-DISC-20260512-0001",
        "version": "v1.0",
        "finding_id": "AG-EV-TEST-0001",
        "engine_origin": "manual",
        "event_type": event_type,
        "timestamp": "2026-05-12T00:00:00Z",
        "actor": "577_industries_pi",
        "vendor_contact": vendor_contact,
        "notes_hash": notes_hash,
        "payload_hash_only": "a" * 64,
        "provenance": {
            "generated_by": "test",
            "generated_at": "2026-05-12T00:00:00Z",
            "source": "tests/test_sanitize_check_v04_rules.py",
            "private_by_default": False,
        },
        "safety_flags": [],
    }


def test_rule7_disclosure_event_private_event_type_fails(tmp_path: Path) -> None:
    """A disclosure_event with event_type='vendor_contacted' is NOT in the
    public-safe whitelist {cve_assigned, cve_published, disclosure_public}
    and must trip Rule 7 in a public export."""
    root = tmp_path / "leaky-disclosure"
    shutil.copytree(CLEAN, root)
    bad = _disclosure_event(
        event_type="vendor_contacted",
        vendor_contact=None,
        notes_hash=None,
    )
    (root / "disclosure_events.json").write_text(
        json.dumps(_build_disclosure_doc(bad), indent=2)
    )
    report = scan_export_tree(root)
    assert not report.ok
    rules = {f.rule for f in report.failures}
    assert "disclosure_event_private_event_type" in rules, rules


def test_rule7_disclosure_event_vendor_contact_field_populated_fails(
    tmp_path: Path,
) -> None:
    """vendor_contact must be an org id only (no @). An '@' value fails."""
    root = tmp_path / "leaky-disclosure"
    shutil.copytree(CLEAN, root)
    bad = _disclosure_event(
        event_type="cve_published",
        vendor_contact="security-team@example.com",
        notes_hash=None,
    )
    (root / "disclosure_events.json").write_text(
        json.dumps(_build_disclosure_doc(bad), indent=2)
    )
    report = scan_export_tree(root)
    assert not report.ok
    rules = {f.rule for f in report.failures}
    assert "disclosure_event_vendor_contact_populated" in rules, rules


def test_rule7_disclosure_event_notes_hash_populated_fails(
    tmp_path: Path,
) -> None:
    """notes_hash must be null in public exports."""
    root = tmp_path / "leaky-disclosure"
    shutil.copytree(CLEAN, root)
    bad = _disclosure_event(
        event_type="cve_published",
        vendor_contact=None,
        notes_hash="b" * 64,
    )
    (root / "disclosure_events.json").write_text(
        json.dumps(_build_disclosure_doc(bad), indent=2)
    )
    report = scan_export_tree(root)
    assert not report.ok
    rules = {f.rule for f in report.failures}
    assert "disclosure_event_notes_hash_populated" in rules, rules


def test_rule7_clean_disclosure_event_passes(tmp_path: Path) -> None:
    """A clean disclosure_event (public event_type, no vendor_contact,
    null notes_hash) passes Rule 7."""
    root = tmp_path / "clean-disclosure"
    shutil.copytree(CLEAN, root)
    good = _disclosure_event(
        event_type="cve_published",
        vendor_contact="signal_org",
        notes_hash=None,
    )
    (root / "disclosure_events.json").write_text(
        json.dumps(_build_disclosure_doc(good), indent=2)
    )
    report = scan_export_tree(root)
    rules = {f.rule for f in report.failures}
    assert "disclosure_event_private_event_type" not in rules
    assert "disclosure_event_vendor_contact_populated" not in rules
    assert "disclosure_event_notes_hash_populated" not in rules


# ---------------------------------------------------------------------------
# Rule 8 — SARIF source snippets
# ---------------------------------------------------------------------------


def _invariant_violation(
    *,
    include_source_snippet: bool,
    location_extra: dict | None = None,
) -> dict:
    location = {
        "repo_url": "https://github.com/example/target.git",
        "commit": "abc123",
        "path": "src/parse.c",
        "start_line": 42,
    }
    if location_extra:
        location.update(location_extra)
    record = {
        "violation_id": "AG-IV-TEST-001",
        "version": "v1.0",
        "discovery_engine": "invariantcheck",
        "invariant_id": "INV-01",
        "target_id": "libwebp",
        "rule_id": "cwe-119",
        "severity": "warning",
        "location": location,
        "sarif_result_uri": "private/sarif/INV-01.sarif",
        "provenance": {
            "generated_by": "test",
            "generated_at": "2026-05-12T00:00:00Z",
            "source": "tests/test_sanitize_check_v04_rules.py",
            "private_by_default": False,
        },
        "safety_flags": [],
    }
    if include_source_snippet:
        record["location"]["source_snippet"] = (
            "int main() {\n  char buf[10];\n  strcpy(buf, argv[1]);\n  return 0;\n}"
        )
    return record


def _build_iv_doc(record: dict) -> dict:
    return {
        "version": "v1.0",
        "tool_output_type": "public_sanitized_export",
        "safety_posture": "sanitized_candidate",
        "records": [record],
    }


def test_rule8_invariant_violation_with_source_snippet_fails(
    tmp_path: Path,
) -> None:
    """invariant_violation with source_snippet inside location fails Rule 8."""
    root = tmp_path / "leaky-iv"
    shutil.copytree(CLEAN, root)
    bad = _invariant_violation(include_source_snippet=True)
    (root / "invariant_violations.json").write_text(
        json.dumps(_build_iv_doc(bad), indent=2)
    )
    report = scan_export_tree(root)
    assert not report.ok
    rules = {f.rule for f in report.failures}
    assert "invariant_violation_source_snippet" in rules, rules


def test_rule8_clean_invariant_violation_passes(tmp_path: Path) -> None:
    """Clean invariant_violation (location is uri+commit+path+startLine
    only) passes Rule 8."""
    root = tmp_path / "clean-iv"
    shutil.copytree(CLEAN, root)
    good = _invariant_violation(include_source_snippet=False)
    (root / "invariant_violations.json").write_text(
        json.dumps(_build_iv_doc(good), indent=2)
    )
    report = scan_export_tree(root)
    rules = {f.rule for f in report.failures}
    assert "invariant_violation_source_snippet" not in rules


# ---------------------------------------------------------------------------
# Rule 9 — crash record completeness
# ---------------------------------------------------------------------------


def _crash(
    *,
    crash_sha256: str | None,
    extra_fields: dict | None = None,
) -> dict:
    record = {
        "crash_id": "AG-CRASH-TEST-001",
        "version": "v1.0",
        "discovery_engine": "harnessgen",
        "harness_id": "libwebp_decode_harness",
        "stack_trace_hash": "a" * 64,
        "crash_class": "ASAN heap-buffer-overflow",
        "minimized_input_size_bytes": 64,
        "novelty": "appears_novel",
        "provenance": {
            "generated_by": "test",
            "generated_at": "2026-05-12T00:00:00Z",
            "source": "tests/test_sanitize_check_v04_rules.py",
            "private_by_default": False,
        },
        "safety_flags": [],
    }
    if crash_sha256 is not None:
        record["crash_sha256"] = crash_sha256
    if extra_fields:
        record.update(extra_fields)
    return record


def _build_crash_doc(record: dict) -> dict:
    return {
        "version": "v1.0",
        "tool_output_type": "public_sanitized_export",
        "safety_posture": "sanitized_candidate",
        "records": [record],
    }


def test_rule9_crash_missing_sha256_fails(tmp_path: Path) -> None:
    """Crash record without crash_sha256 fails Rule 9."""
    root = tmp_path / "leaky-crash"
    shutil.copytree(CLEAN, root)
    bad = _crash(crash_sha256=None)
    (root / "crashes.json").write_text(
        json.dumps(_build_crash_doc(bad), indent=2)
    )
    report = scan_export_tree(root)
    assert not report.ok
    rules = {f.rule for f in report.failures}
    assert "crash_record_missing_sha256" in rules, rules


def test_rule9_crash_with_raw_witness_fails(tmp_path: Path) -> None:
    """Crash record with raw_witness (any payload-bearing field) fails Rule 9."""
    root = tmp_path / "leaky-crash"
    shutil.copytree(CLEAN, root)
    bad = _crash(
        crash_sha256="c" * 64,
        extra_fields={"raw_witness": "raw bytes here"},
    )
    (root / "crashes.json").write_text(
        json.dumps(_build_crash_doc(bad), indent=2)
    )
    report = scan_export_tree(root)
    assert not report.ok
    rules = {f.rule for f in report.failures}
    # raw_witness is now in _PAYLOAD_FIELD_NAMES, so embedded_crash_payload fires
    assert "embedded_crash_payload" in rules or "crash_record_payload_field" in rules, rules


def test_rule9_crash_with_raw_corpus_input_fails(tmp_path: Path) -> None:
    root = tmp_path / "leaky-crash"
    shutil.copytree(CLEAN, root)
    bad = _crash(
        crash_sha256="c" * 64,
        extra_fields={"raw_corpus_input": "AABBCCDD"},
    )
    (root / "crashes.json").write_text(
        json.dumps(_build_crash_doc(bad), indent=2)
    )
    report = scan_export_tree(root)
    assert not report.ok
    rules = {f.rule for f in report.failures}
    assert "embedded_crash_payload" in rules or "crash_record_payload_field" in rules, rules


def test_rule9_clean_crash_passes(tmp_path: Path) -> None:
    """Crash with crash_sha256 and no payload fields passes Rule 9."""
    root = tmp_path / "clean-crash"
    shutil.copytree(CLEAN, root)
    good = _crash(crash_sha256="c" * 64)
    (root / "crashes.json").write_text(
        json.dumps(_build_crash_doc(good), indent=2)
    )
    report = scan_export_tree(root)
    rules = {f.rule for f in report.failures}
    assert "crash_record_missing_sha256" not in rules
    assert "crash_record_payload_field" not in rules
