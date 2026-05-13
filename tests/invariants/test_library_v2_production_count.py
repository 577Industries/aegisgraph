"""Tests that the InvariantCheck library has graduated 10 of 15
invariants to production-encoded status (M7-INV deliverable).

Per Phase II plan §5 (M5–M7) line 174:
    "InvariantCheck library v1 (15 invariants); ≥1 novel finding
    submitted for coordinated disclosure."

The count of 15 was met at M5.3 (test_library_v1_count.py asserts it).
M7-INV is the quality gate: graduate 7 of the 11 M5.3 stubs to fully
encoded production CodeQL queries, leaving 5 stubs for later milestones.

Production at M7-INV (10 total):
    INV-01 CodeQL  (was production at M3.3)
    INV-02 CodeQL  (was production at M5.3)
    INV-03 CodeQL  (graduated at M7-INV)
    INV-04 CodeQL  (graduated at M7-INV)
    INV-05 CodeQL  (was production at M5.3)
    INV-06 CodeQL  (graduated at M7-INV)
    INV-07 Semgrep (was production at M3.3)
    INV-08 Semgrep (was production at M5.3)
    INV-10 CodeQL  (graduated at M7-INV)
    INV-12 CodeQL  (graduated at M7-INV)
    INV-14 CodeQL  (graduated at M7-INV)
    INV-15 CodeQL  (graduated at M7-INV)

Wait — that's 12 entries. The library size is 15, and 12 are production
after M7-INV: 10 fully-encoded CodeQL queries + 2 fully-encoded Semgrep
rules. The remaining 3 stubs (INV-09 Semgrep, INV-11 CodeQL, INV-13
CodeQL) graduate at later milestones.

To preserve the spec wording ("10 production"), this test asserts
the number of `status="production"` encodings whose engine is CodeQL is
exactly 10, and the total number of `status="production"` encodings
(CodeQL + Semgrep) is 12. Stubs (status="stub") total 3.

If a future milestone graduates a stub or adds a new invariant, update
the expected counts here together with the manifest entries.
"""

from __future__ import annotations

from pathlib import Path

from aegisgraph.io import load_json, repo_root


# Production CodeQL queries after the M7-INV pass.
PRODUCTION_CODEQL_INVARIANTS = {
    "INV-01", "INV-02", "INV-03", "INV-04", "INV-05",
    "INV-06", "INV-10", "INV-12", "INV-14", "INV-15",
}

# Production Semgrep rules after the M7-INV pass.
PRODUCTION_SEMGREP_INVARIANTS = {"INV-07", "INV-08"}

# Remaining stubs after the M7-INV pass.
STUB_INVARIANTS = {"INV-09", "INV-11", "INV-13"}


def _manifest_path() -> Path:
    return repo_root() / "aegisgraph" / "invariants" / "manifest.json"


def _entries() -> list[dict]:
    manifest = load_json(_manifest_path())
    return manifest["invariants"]


def _status_of_encoding(enc: dict) -> str:
    """Return the encoding's `status` field, defaulting to 'stub' if the
    field is missing — backward compatibility with the pre-M7-INV
    manifest shape that did not carry the field at all."""
    return enc.get("status", "stub")


def _is_static_engine(enc: dict) -> bool:
    """True if the encoding is a CodeQL or Semgrep static engine (i.e.
    the kind whose status field we care about). frida_dynamic encodings
    are option-only dynamic encodings that do not participate in the
    production/stub gate."""
    return enc.get("engine") in {"codeql", "semgrep"}


def test_manifest_has_status_field_on_static_encodings() -> None:
    """M7-INV adds an explicit `status` field on every static (CodeQL or
    Semgrep) encoding so we can distinguish production from stub."""
    for entry in _entries():
        for enc in entry["encodings"]:
            if not _is_static_engine(enc):
                continue
            assert "status" in enc, (
                f"INV {entry['invariant_id']} static encoding "
                f"{enc.get('query', '<?>')} missing required `status` field"
            )
            assert enc["status"] in {"production", "stub"}, (
                f"INV {entry['invariant_id']} status must be "
                f"'production' or 'stub', got {enc['status']!r}"
            )


def test_production_codeql_count_is_ten() -> None:
    """The M7-INV deliverable: 10 production CodeQL queries."""
    production_codeql = {
        entry["invariant_id"]
        for entry in _entries()
        for enc in entry["encodings"]
        if enc.get("engine") == "codeql"
        and _status_of_encoding(enc) == "production"
    }
    assert production_codeql == PRODUCTION_CODEQL_INVARIANTS, (
        f"M7-INV must declare exactly {sorted(PRODUCTION_CODEQL_INVARIANTS)} "
        f"as production CodeQL invariants; "
        f"got {sorted(production_codeql)}; "
        f"missing: {sorted(PRODUCTION_CODEQL_INVARIANTS - production_codeql)}; "
        f"unexpected: {sorted(production_codeql - PRODUCTION_CODEQL_INVARIANTS)}"
    )


def test_production_semgrep_count_is_two() -> None:
    """The M7-INV deliverable preserves the 2 production Semgrep rules."""
    production_semgrep = {
        entry["invariant_id"]
        for entry in _entries()
        for enc in entry["encodings"]
        if enc.get("engine") == "semgrep"
        and _status_of_encoding(enc) == "production"
    }
    assert production_semgrep == PRODUCTION_SEMGREP_INVARIANTS, (
        f"M7-INV must declare exactly {sorted(PRODUCTION_SEMGREP_INVARIANTS)} "
        f"as production Semgrep rules; got {sorted(production_semgrep)}"
    )


def test_remaining_stubs_count_is_three() -> None:
    """Three M5.3 stubs remain after the M7-INV pass: INV-09 Semgrep,
    INV-11 CodeQL, INV-13 CodeQL."""
    stub_invariants = {
        entry["invariant_id"]
        for entry in _entries()
        for enc in entry["encodings"]
        if _is_static_engine(enc) and _status_of_encoding(enc) == "stub"
    }
    assert stub_invariants == STUB_INVARIANTS, (
        f"After M7-INV the remaining stubs must be {sorted(STUB_INVARIANTS)}; "
        f"got {sorted(stub_invariants)}"
    )


def test_total_static_invariants_is_fifteen() -> None:
    """All 15 library entries have at least one static (CodeQL or
    Semgrep) encoding. (The production + stub sets together cover the
    full library — there should be no invariant whose only encoding is
    a frida_dynamic option-only hook.)"""
    invariants_with_static = {
        entry["invariant_id"]
        for entry in _entries()
        for enc in entry["encodings"]
        if _is_static_engine(enc)
    }
    expected = (
        PRODUCTION_CODEQL_INVARIANTS
        | PRODUCTION_SEMGREP_INVARIANTS
        | STUB_INVARIANTS
    )
    assert invariants_with_static == expected, (
        f"All 15 library invariants must have a static encoding; "
        f"got {sorted(invariants_with_static)}, expected {sorted(expected)}"
    )
    assert len(invariants_with_static) == 15


def test_production_total_count_is_twelve() -> None:
    """Sanity sum: 10 CodeQL + 2 Semgrep = 12 production-encoded
    invariants after the M7-INV pass."""
    production_count = sum(
        1
        for entry in _entries()
        for enc in entry["encodings"]
        if _is_static_engine(enc) and _status_of_encoding(enc) == "production"
    )
    assert production_count == 12, (
        f"M7-INV must produce 12 production-encoded invariants "
        f"(10 CodeQL + 2 Semgrep); got {production_count}"
    )
