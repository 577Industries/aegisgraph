"""Tests that the InvariantCheck library has reached its M5.3 / M7
deliverable size: 15 invariants total.

Per Phase II plan §5 (M5–M7) line 174:
    "InvariantCheck library v1 (15 invariants); ≥1 novel finding submitted
    for coordinated disclosure."

And §5 line 156:
    "T-M5.3 InvariantCheck: ship invariants 02–06, 08, 10, 12, 14, 15
    (total 15)"

At M3.3 the library shipped with 5 invariants (INV-01, -07, -09, -11, -13).
T-M5.3 expands the library to 15 by adding INV-02, -03, -04, -05, -06,
-08, -10, -12, -14, -15.

This test is the count gate: it asserts the manifest has exactly 15
entries with the expected IDs. If a future milestone adds invariants 16+
(per Phase II plan M8.2 / M11.1 — library v2/v3), update both the count
and the expected ID set together.

Library version expectations:
    * library_version metadata field is bumped from `m3.3-scaffold-v0`
      to `m5.3-library-v1`.
"""

from __future__ import annotations

from pathlib import Path

from aegisgraph.io import load_json, repo_root


M5_3_INVARIANTS = {
    "INV-01",
    "INV-02",
    "INV-03",
    "INV-04",
    "INV-05",
    "INV-06",
    "INV-07",
    "INV-08",
    "INV-09",
    "INV-10",
    "INV-11",
    "INV-12",
    "INV-13",
    "INV-14",
    "INV-15",
}


def _manifest_path() -> Path:
    return repo_root() / "aegisgraph" / "invariants" / "manifest.json"


def _load_manifest() -> dict:
    return load_json(_manifest_path())


def _entries() -> list[dict]:
    manifest = _load_manifest()
    if isinstance(manifest, dict):
        return manifest.get("invariants", [])
    if isinstance(manifest, list):
        return manifest
    raise AssertionError(f"manifest.json must be a dict or list, got {type(manifest)}")


def test_library_v1_count_is_fifteen() -> None:
    """T-M5.3 deliverable: 15 invariants encoded in the library."""
    entries = _entries()
    assert len(entries) == 15, (
        f"M5.3 library v1 must contain exactly 15 invariants; "
        f"found {len(entries)}"
    )


def test_library_v1_invariant_ids_match_expected_set() -> None:
    """Every M5.3 deliverable invariant ID is present, no extras."""
    entries = _entries()
    ids = {entry["invariant_id"] for entry in entries}
    assert ids == M5_3_INVARIANTS, (
        f"M5.3 library v1 invariant-ID set must be {sorted(M5_3_INVARIANTS)}, "
        f"got {sorted(ids)}; "
        f"missing: {sorted(M5_3_INVARIANTS - ids)}; "
        f"unexpected: {sorted(ids - M5_3_INVARIANTS)}"
    )


def test_library_version_bumped_to_m5_3() -> None:
    """The library_version metadata field reflects the M5.3 deliverable."""
    manifest = _load_manifest()
    library_version = manifest.get("library_version", "")
    assert "m5.3" in library_version.lower() or "v1" in library_version.lower(), (
        f"library_version should reflect M5.3 / v1 milestone, "
        f"got {library_version!r}"
    )


def test_new_m5_3_invariants_resolve_to_files() -> None:
    """All 10 new M5.3 query/rule files exist on disk."""
    manifest_dir = _manifest_path().parent
    new_ids = M5_3_INVARIANTS - {"INV-01", "INV-07", "INV-09", "INV-11", "INV-13"}
    for entry in _entries():
        if entry["invariant_id"] not in new_ids:
            continue
        for enc in entry["encodings"]:
            if enc["engine"] in {"codeql", "semgrep"}:
                resolved = manifest_dir / enc["query"]
                assert resolved.is_file(), (
                    f"INV {entry['invariant_id']} new encoding "
                    f"{enc['engine']}/{enc['query']} does not resolve to a "
                    f"real file (looked for {resolved})"
                )
                # The new file must be non-trivially populated (either a
                # full encoding or a rich-comment stub). Reject empty files.
                assert resolved.stat().st_size > 200, (
                    f"INV {entry['invariant_id']} encoding "
                    f"{enc['query']} is unexpectedly small "
                    f"({resolved.stat().st_size} bytes); stubs MUST carry a "
                    f"rich header/comment block per the M5.3 spec"
                )
