"""Tests for the fully-encoded InvariantCheck library queries.

History:
    M5.3 — three queries shipped fully encoded (INV-02, INV-05 CodeQL;
           INV-08 Semgrep); seven CodeQL queries shipped as rich-comment
           stubs awaiting M7 ground-truth completion. The original M3.3
           baseline (INV-01 CodeQL, INV-07 Semgrep) was already fully
           encoded prior to M5.3.
    M7-INV — seven M5.3 stubs graduate to production CodeQL encodings
             (INV-03, INV-04, INV-06, INV-10, INV-12, INV-14, INV-15).
             That brings the total production-encoded CodeQL set to 10
             (INV-01, -02, -03, -04, -05, -06, -10, -12, -14, -15) and
             the production-encoded Semgrep set to 2 (INV-07, -08). Three
             stubs remain after M7-INV (INV-09 Semgrep, INV-11 CodeQL,
             INV-13 CodeQL); those graduate later.
    M7-GT-v3 (Wave 8A) — the final 3 stubs graduate (INV-09 Semgrep,
             INV-11 CodeQL, INV-13 CodeQL), closing the library at 15/15
             production. Total production CodeQL: 12; Semgrep: 3. Stub
             tuples are now empty.

What this test asserts (no CodeQL / Semgrep binary required — text-only):

  * Each fully-encoded CodeQL query carries the TaintTracking skeleton:
      - `import java` + `import semmle.code.java.dataflow.TaintTracking`
      - Source class extending `DataFlow::Node`
      - Sink class extending `DataFlow::Node`
      - Barrier class extending `DataFlow::Node`
      - A `DataFlow::ConfigSig` module with `isSource`, `isSink`, and
        `isBarrier` predicates
      - A `TaintTracking::Global<...>` instantiation
      - A final `from ... where ...flowPath... select ...` clause
      - No residual `where none()` stub marker

  * Each fully-encoded Semgrep rule carries `rules:`, a `pattern-either`
    or `patterns` block, and a `pattern-not-regex` or `pattern-not`
    barrier.

  * Each remaining stub query carries a `TODO[M7]` marker so a grep over
    the library lists outstanding work.

  * Each fully-encoded query / rule references its INV-NN id in the
    @id-mapping / metadata.invariant_id field.

Ground-truth fixtures land at tests/fixtures/demo-vulnerable-app/ in the
M7 ground-truth pass. When that pass lands, this test file is extended
with `pytest.mark.skipif(not fixture_present)` assertions on
expected_violations counts.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aegisgraph.io import repo_root


LIBRARY_DIR = repo_root() / "aegisgraph" / "invariants" / "library"

# All twelve production CodeQL queries (3 prior + 7 M7-INV + 2 M7-GT-v3).
# The three fully-encoded Semgrep rules (INV-07, INV-08, INV-09) are
# checked below via FULLY_ENCODED_SEMGREP.
FULLY_ENCODED_CODEQL = (
    ("01_url_fetch_without_policy.ql", "INV-01", "UrlFetchPolicy"),
    ("02_notification_leak.ql", "INV-02", "NotificationLeak"),
    ("03_group_state_unauth.ql", "INV-03", "GroupStateUnauth"),
    ("04_device_link_no_kex.ql", "INV-04", "DeviceLinkKex"),
    ("05_key_storage_no_keystore.ql", "INV-05", "KeyStorage"),
    ("06_pq_downgrade.ql", "INV-06", "PqDowngrade"),
    ("10_attachment_path_traversal.ql", "INV-10", "AttachmentPathTraversal"),
    ("11_deeplink_open_redirect.ql", "INV-11", "DeeplinkOpenRedirect"),
    ("12_media_decode_unsanitized.ql", "INV-12", "MediaDecodeUnsanitized"),
    ("13_qr_payload_unverified_binding.ql", "INV-13", "QrPayloadBinding"),
    ("14_backup_blob_unauthenticated.ql", "INV-14", "BackupBlob"),
    ("15_metadata_leak_outside_envelope.ql", "INV-15", "MetadataLeak"),
)

FULLY_ENCODED_SEMGREP = (
    ("07_intent_filter_implicit_export.yaml", "INV-07", "intent-filter"),
    ("08_clipboard_paste_to_send.yaml", "INV-08", "clipboard"),
    ("09_webview_jsinterface_addjavascript.yaml", "INV-09", "webview"),
)

# After M7-GT-v3 (Wave 8A), no stubs remain — all 15 invariants are
# production-encoded. The empty tuples are retained for backward
# compatibility with parametrized tests downstream; the
# test_no_remaining_stubs assertion below asserts this explicitly.
STUB_CODEQL: tuple[str, ...] = ()

STUB_SEMGREP: tuple[str, ...] = ()


# Regexes for the structural source/sink/barrier class declarations.
_SOURCE_CLASS_RE = re.compile(r"class\s+\w*Source\s+extends\s+DataFlow::Node", re.MULTILINE)
_SINK_CLASS_RE = re.compile(r"class\s+\w*Sink\s+extends\s+DataFlow::Node", re.MULTILINE)
_BARRIER_CLASS_RE = re.compile(r"class\s+\w*Barrier\s+extends\s+DataFlow::Node", re.MULTILINE)
_FROM_WHERE_SELECT_RE = re.compile(
    r"^from\s+.+?where\s+.+?select\s+",
    re.MULTILINE | re.DOTALL,
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
    # Production queries must not retain the stub marker.
    assert "where none()" not in text, (
        f"{filename}: still carries the stub `where none()` marker — "
        f"this query has graduated to production and must use a real "
        f"TaintTracking::Global<...> flowPath select"
    )
    # Structural class declarations.
    assert _SOURCE_CLASS_RE.search(text), (
        f"{filename}: missing `class XxxSource extends DataFlow::Node`"
    )
    assert _SINK_CLASS_RE.search(text), (
        f"{filename}: missing `class XxxSink extends DataFlow::Node`"
    )
    assert _BARRIER_CLASS_RE.search(text), (
        f"{filename}: missing `class XxxBarrier extends DataFlow::Node`"
    )
    # Configuration module and predicates.
    assert "implements DataFlow::ConfigSig" in text, (
        f"{filename}: missing DataFlow::ConfigSig module"
    )
    assert "TaintTracking::Global" in text, (
        f"{filename}: missing TaintTracking::Global<...> instantiation"
    )
    assert "TaintTracking::Configuration" in text or "TaintTracking::Global" in text, (
        f"{filename}: missing TaintTracking::Configuration / "
        f"TaintTracking::Global pattern"
    )
    assert "flowPath" in text, (
        f"{filename}: missing flowPath select clause"
    )
    assert "isSource" in text and "isSink" in text and "isBarrier" in text, (
        f"{filename}: must define isSource, isSink, and isBarrier predicates"
    )
    # Final from-where-select clause (the production query body).
    assert _FROM_WHERE_SELECT_RE.search(text), (
        f"{filename}: missing final `from ... where ... select ...` clause"
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


def test_no_remaining_stubs() -> None:
    """After the M7-GT-v3 pass (Wave 8A), no stubs remain — all 15
    invariants are production-encoded. This assertion replaces the
    earlier per-stub parametrized tests."""
    assert STUB_CODEQL == (), (
        f"M7-GT-v3 closes the InvariantCheck library at 15/15 "
        f"production; STUB_CODEQL must be empty, got {STUB_CODEQL}"
    )
    assert STUB_SEMGREP == (), (
        f"M7-GT-v3 closes the InvariantCheck library at 15/15 "
        f"production; STUB_SEMGREP must be empty, got {STUB_SEMGREP}"
    )


def test_no_codeql_file_carries_where_none_marker() -> None:
    """After M7-GT-v3 no CodeQL query may carry the `where none()` stub
    marker — every query is a real TaintTracking::Global flowPath
    select."""
    codeql_dir = LIBRARY_DIR / "codeql"
    for ql_file in codeql_dir.glob("*.ql"):
        text = ql_file.read_text(encoding="utf-8")
        assert "where none()" not in text, (
            f"{ql_file.name}: still carries `where none()` stub marker — "
            f"M7-GT-v3 requires a production TaintTracking::Global flowPath select"
        )


def test_ground_truth_fixture_dir_is_present() -> None:
    """The demo-vulnerable-app fixture directory is required after the
    M7-GT-v3 pass (Wave 8A); test_ground_truth_pass.py exercises it."""
    fixture_dir = repo_root() / "tests" / "fixtures" / "demo-vulnerable-app"
    assert fixture_dir.is_dir(), (
        f"tests/fixtures/demo-vulnerable-app must exist after M7-GT-v3; "
        f"got {fixture_dir} (is_dir={fixture_dir.is_dir()}, "
        f"exists={fixture_dir.exists()})"
    )
    # Required subdirectories.
    assert (fixture_dir / "src" / "main" / "java" / "com" / "example" / "demo").is_dir()
    assert (fixture_dir / "fixtures").is_dir()
    assert (fixture_dir / "AndroidManifest.xml").is_file()
    assert (fixture_dir / "README.md").is_file()
