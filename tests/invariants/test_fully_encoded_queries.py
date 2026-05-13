"""Tests for the three M5.3 fully-encoded queries (INV-02, INV-05, INV-08).

The M5.3 deliverable picks the three highest-value queries to fully encode
(remaining seven ship as rich-comment stubs scheduled for M7 ground-truth
completion):

    INV-02  notification leak              CodeQL (path-problem)
    INV-05  key storage no keystore        CodeQL (path-problem)
    INV-08  clipboard paste to send        Semgrep (pattern + barrier)

Why these three?

    They have the crispest, most-mechanical source/sink/barrier shapes in
    the M5.3 batch, which makes the encoding stable and the ground-truth
    pass at M7 trivial. The remaining seven invariants are
    target-architecture-dependent enough that we want a real ground-truth
    fixture in hand before locking the encoding.

What this test asserts (no CodeQL / Semgrep binary required — text-only):

  * Each fully-encoded query carries the structural skeleton we promised:
      - CodeQL: explicit Source / Sink / Barrier classes, a
        TaintTracking::ConfigSig module, and a final `from ... where
        ...flowPath... select ...` clause.
      - Semgrep: `rules:` block with a `pattern-either` (sources) and a
        `pattern-not-regex` (barriers), and a non-stub message.

  * Each stub query carries a `TODO[M7]` marker so a grep over the
    library can list outstanding work.

  * Each fully-encoded query / rule references its INV-NN id in the
    @id-mapping / metadata.invariant_id field.

Ground-truth fixtures land at tests/fixtures/demo-vulnerable-app/ in the
M7 ground-truth pass (Phase II plan §5 line 156 mentions T-M5.4 as the
real-target run; the synthetic fixtures land alongside). When that pass
lands, this test file is extended with `pytest.mark.skipif(not
fixture_present)` assertions on expected_violations counts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisgraph.io import repo_root


LIBRARY_DIR = repo_root() / "aegisgraph" / "invariants" / "library"

FULLY_ENCODED_CODEQL = (
    ("02_notification_leak.ql", "INV-02", "NotificationLeak"),
    ("05_key_storage_no_keystore.ql", "INV-05", "KeyStorage"),
)

FULLY_ENCODED_SEMGREP = (
    ("08_clipboard_paste_to_send.yaml", "INV-08", "clipboard"),
)

STUB_CODEQL = (
    "03_group_state_unauth.ql",
    "04_device_link_no_kex.ql",
    "06_pq_downgrade.ql",
    "10_attachment_path_traversal.ql",
    "12_media_decode_unsanitized.ql",
    "14_backup_blob_unauthenticated.ql",
    "15_metadata_leak_outside_envelope.ql",
)


@pytest.mark.parametrize("filename,inv_id,name_marker", FULLY_ENCODED_CODEQL)
def test_fully_encoded_codeql_has_taint_config(
    filename: str, inv_id: str, name_marker: str
) -> None:
    """Each fully-encoded CodeQL query must carry the TaintTracking
    skeleton (Source / Sink / Barrier class + ConfigSig module +
    flowPath select)."""
    text = (LIBRARY_DIR / "codeql" / filename).read_text(encoding="utf-8")
    assert "import java" in text, f"{filename}: missing `import java`"
    assert "import semmle.code.java.dataflow.TaintTracking" in text, (
        f"{filename}: missing TaintTracking import"
    )
    assert "extends DataFlow::Node" in text, (
        f"{filename}: missing DataFlow::Node-derived source/sink class"
    )
    assert "implements DataFlow::ConfigSig" in text, (
        f"{filename}: missing DataFlow::ConfigSig module"
    )
    assert "TaintTracking::Global" in text, (
        f"{filename}: missing TaintTracking::Global<...> instantiation"
    )
    assert "flowPath" in text, (
        f"{filename}: missing flowPath select clause"
    )
    assert "isSource" in text and "isSink" in text and "isBarrier" in text, (
        f"{filename}: must define isSource, isSink, and isBarrier predicates"
    )
    assert inv_id in text, f"{filename}: missing {inv_id} reference"


@pytest.mark.parametrize("filename,inv_id,name_marker", FULLY_ENCODED_SEMGREP)
def test_fully_encoded_semgrep_has_rule_structure(
    filename: str, inv_id: str, name_marker: str
) -> None:
    """Each fully-encoded Semgrep rule must carry the rules / message /
    metadata / pattern blocks."""
    text = (LIBRARY_DIR / "semgrep" / filename).read_text(encoding="utf-8")
    assert "rules:" in text, f"{filename}: missing rules: top-level key"
    assert "message:" in text, f"{filename}: missing message: field"
    assert "metadata:" in text, f"{filename}: missing metadata: field"
    assert f"invariant_id: {inv_id}" in text, (
        f"{filename}: missing invariant_id: {inv_id}"
    )
    assert "pattern-either" in text or "patterns" in text, (
        f"{filename}: missing pattern-either / patterns block"
    )
    assert "pattern-not-regex" in text or "pattern-not" in text, (
        f"{filename}: missing barrier (pattern-not-regex / pattern-not)"
    )


@pytest.mark.parametrize("filename", STUB_CODEQL)
def test_stub_carries_m7_todo_marker(filename: str) -> None:
    """Each M5.3 stub must carry a TODO[M7] marker so a grep over the
    library lists outstanding ground-truth-completion work."""
    text = (LIBRARY_DIR / "codeql" / filename).read_text(encoding="utf-8")
    assert "TODO[M7]" in text, (
        f"{filename}: stub missing TODO[M7] marker — needed so M7's "
        f"completion sweep can find it"
    )
    # Stubs must have an INV-NN reference in the header.
    assert "@id-mapping INV-" in text, (
        f"{filename}: stub missing @id-mapping INV-NN tag"
    )
    # Stubs use the trivial `where none()` form so codeql accepts the
    # file without producing matches.
    assert "where none()" in text, (
        f"{filename}: stub should use `where none()` so the query is a "
        f"syntactic-only placeholder"
    )


@pytest.mark.parametrize("filename", STUB_CODEQL)
def test_stub_has_rich_intent_block(filename: str) -> None:
    """Each stub must carry the intent comment block describing planned
    sources / sinks / barriers (per M5.3 spec)."""
    text = (LIBRARY_DIR / "codeql" / filename).read_text(encoding="utf-8")
    # All three taint-config concept words present in the comment block.
    for keyword in ("Sources", "Sinks", "Barriers"):
        assert keyword in text, (
            f"{filename}: stub intent block missing '{keyword}:' section"
        )


def test_ground_truth_fixture_dir_is_optional() -> None:
    """The demo-vulnerable-app fixture directory is the planned home of
    real ground-truth assertions for INV-02 / INV-05 / INV-08. At M5.3
    the directory may or may not exist — we accept both cases.

    When the directory IS present, future M7 assertions will validate
    expected_violations counts against synthetic-vulnerable Java/Kotlin
    snippets. Until then, this test is informational only.
    """
    fixture_dir = repo_root() / "tests" / "fixtures" / "demo-vulnerable-app"
    # We accept either present or absent at M5.3. The M7 ground-truth
    # pass creates the directory and populates it; until then the
    # absence is the expected state.
    assert fixture_dir.is_dir() or not fixture_dir.exists(), (
        f"tests/fixtures/demo-vulnerable-app exists but is not a "
        f"directory: {fixture_dir}"
    )
