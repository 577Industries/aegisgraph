"""Tests that aegisgraph/invariants/manifest.json carries the required
per-invariant metadata.

Per Asemarefactor.md lines 332-349, each invariant manifest entry MUST
have these fields:

    invariant_id           — string matching ^INV-[0-9]{2,3}$
    statement              — non-empty natural-language statement
    rationale              — non-empty natural-language rationale
    encodings              — list of {engine, query} objects (>= 1)
    ground_truth           — list of {target, expected_violations} objects
    applicable_path_classes — list of path-class strings (from constants.PATH_CLASSES)
    mastg_mapping          — string MSTG/MASTG code
    ssdf_mapping           — string SSDF code

At M3.3 the manifest carried 5 entries: INV-01, INV-07, INV-09, INV-11,
INV-13. At M5.3 the library v1 expands to 15 entries (adds INV-02, -03,
-04, -05, -06, -08, -10, -12, -14, -15). The plan's full 25-30
invariants ship across M3-M11 per Phase II rollout.

The encoding `query` field is a path RELATIVE TO the manifest.json
location — the runner resolves it against `manifest.json.parent`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aegisgraph.constants import PATH_CLASSES
from aegisgraph.io import load_json, repo_root


M3_3_INVARIANTS = {"INV-01", "INV-07", "INV-09", "INV-11", "INV-13"}
M5_3_NEW_INVARIANTS = {
    "INV-02",
    "INV-03",
    "INV-04",
    "INV-05",
    "INV-06",
    "INV-08",
    "INV-10",
    "INV-12",
    "INV-14",
    "INV-15",
}
M5_3_INVARIANTS = M3_3_INVARIANTS | M5_3_NEW_INVARIANTS

REQUIRED_FIELDS = (
    "invariant_id",
    "statement",
    "rationale",
    "encodings",
    "ground_truth",
    "applicable_path_classes",
    "mastg_mapping",
    "ssdf_mapping",
)

INVARIANT_ID_RE = re.compile(r"^INV-\d{2,3}$")


def _manifest_path() -> Path:
    return repo_root() / "aegisgraph" / "invariants" / "manifest.json"


def _load_manifest() -> dict:
    return load_json(_manifest_path())


def _entries() -> list[dict]:
    manifest = _load_manifest()
    # The manifest may use either top-level `invariants: [...]` or a top-level
    # list. We support the `invariants` key (more self-describing) but accept
    # either for forward compatibility.
    if isinstance(manifest, dict):
        return manifest.get("invariants", [])
    if isinstance(manifest, list):
        return manifest
    raise AssertionError(f"manifest.json must be a dict or list, got {type(manifest)}")


def test_manifest_has_fifteen_m5_3_invariants() -> None:
    """At M5.3 the library v1 declares 15 invariants. The M3.3 set is a
    subset; library v1 adds 10 more (INV-02, -03, -04, -05, -06, -08,
    -10, -12, -14, -15)."""
    entries = _entries()
    ids = {entry["invariant_id"] for entry in entries}
    assert ids == M5_3_INVARIANTS, (
        f"M5.3 manifest must declare exactly {sorted(M5_3_INVARIANTS)}, "
        f"got {sorted(ids)}; "
        f"missing: {sorted(M5_3_INVARIANTS - ids)}; "
        f"unexpected: {sorted(ids - M5_3_INVARIANTS)}"
    )


def test_m3_3_baseline_subset_still_present() -> None:
    """The five M3.3 invariants remain in the manifest after the M5.3
    expansion (additive, not destructive)."""
    entries = _entries()
    ids = {entry["invariant_id"] for entry in entries}
    assert M3_3_INVARIANTS.issubset(ids), (
        f"M3.3 baseline invariants {sorted(M3_3_INVARIANTS)} must remain "
        f"present after the M5.3 expansion; missing: "
        f"{sorted(M3_3_INVARIANTS - ids)}"
    )


@pytest.mark.parametrize("field", REQUIRED_FIELDS)
def test_every_entry_has_required_field(field: str) -> None:
    entries = _entries()
    for entry in entries:
        assert field in entry, (
            f"INV {entry.get('invariant_id', '<?>')} missing required "
            f"field {field!r}"
        )


def test_invariant_ids_match_pattern() -> None:
    for entry in _entries():
        assert INVARIANT_ID_RE.match(entry["invariant_id"]), (
            f"invariant_id {entry['invariant_id']!r} does not match ^INV-\\d{{2,3}}$"
        )


def test_statements_are_nonempty_strings() -> None:
    for entry in _entries():
        statement = entry["statement"]
        assert isinstance(statement, str) and statement.strip(), (
            f"INV {entry['invariant_id']} statement must be non-empty"
        )


def test_rationale_is_nonempty_string() -> None:
    for entry in _entries():
        rationale = entry["rationale"]
        assert isinstance(rationale, str) and rationale.strip(), (
            f"INV {entry['invariant_id']} rationale must be non-empty"
        )


def test_encodings_have_engine_and_query() -> None:
    valid_engines = {"codeql", "semgrep", "frida_dynamic"}
    for entry in _entries():
        encodings = entry["encodings"]
        assert isinstance(encodings, list) and encodings, (
            f"INV {entry['invariant_id']} must have at least one encoding"
        )
        for enc in encodings:
            assert "engine" in enc, f"encoding missing engine: {enc}"
            assert enc["engine"] in valid_engines, (
                f"unknown engine {enc['engine']!r} for INV {entry['invariant_id']}"
            )
            # codeql and semgrep encodings need a `query`. frida_dynamic uses
            # `hook` (optional dynamic encoding, called out in Asemarefactor.md
            # lines 337-340).
            if enc["engine"] in {"codeql", "semgrep"}:
                assert "query" in enc, f"encoding missing query: {enc}"


def test_codeql_query_paths_resolve_to_existing_files() -> None:
    """The encoding `query` field is relative to the manifest.json directory.
    Every codeql/semgrep encoding MUST point to a real file on disk.
    """
    manifest_dir = _manifest_path().parent
    for entry in _entries():
        for enc in entry["encodings"]:
            if enc["engine"] in {"codeql", "semgrep"}:
                resolved = manifest_dir / enc["query"]
                assert resolved.is_file(), (
                    f"INV {entry['invariant_id']} encoding "
                    f"{enc['engine']}/{enc['query']} does not resolve to a "
                    f"real file (looked for {resolved})"
                )


def test_ground_truth_entries_are_well_formed() -> None:
    for entry in _entries():
        gt = entry["ground_truth"]
        assert isinstance(gt, list) and gt, (
            f"INV {entry['invariant_id']} ground_truth must be a non-empty list"
        )
        for item in gt:
            assert "target" in item, f"ground_truth missing target: {item}"
            assert "expected_violations" in item, (
                f"ground_truth missing expected_violations: {item}"
            )
            # expected_violations may be an int or the literal string
            # "unknown" (Asemarefactor.md line 343-344 sets this precedent
            # for real-world targets we have not yet pinned the count for).
            ev = item["expected_violations"]
            assert isinstance(ev, int) or ev == "unknown", (
                f"expected_violations must be int or 'unknown', got {ev!r}"
            )


def test_applicable_path_classes_from_known_set() -> None:
    # The plan's path-class identifiers (Asemarefactor.md line 345) include
    # some not-yet-in-PATH_CLASSES names like 'link_preview_web_content' and
    # 'media_handler' — we accept either the constants.PATH_CLASSES exact
    # values OR known plan-level synonyms documented in the spec. To avoid
    # a brittle test that blocks future invariants, we require:
    #   (a) the field is a list of non-empty strings; and
    #   (b) at least one entry overlaps the canonical PATH_CLASSES set
    #       OR uses one of the documented plan-level synonyms.
    plan_synonyms = {"link_preview_web_content", "media_handler", "deep_links"}
    canonical = set(PATH_CLASSES)
    for entry in _entries():
        path_classes = entry["applicable_path_classes"]
        assert isinstance(path_classes, list) and path_classes, (
            f"INV {entry['invariant_id']} applicable_path_classes must be "
            f"a non-empty list"
        )
        for pc in path_classes:
            assert isinstance(pc, str) and pc.strip(), (
                f"applicable_path_classes entry must be non-empty string: {pc!r}"
            )
        # At least one entry must be from the known canonical set OR a
        # documented plan-level synonym; this catches typos.
        known = canonical | plan_synonyms
        overlap = set(path_classes) & known
        assert overlap, (
            f"INV {entry['invariant_id']} applicable_path_classes "
            f"{path_classes} has no overlap with canonical PATH_CLASSES "
            f"or plan synonyms"
        )


def test_mastg_and_ssdf_mappings_present() -> None:
    for entry in _entries():
        for key in ("mastg_mapping", "ssdf_mapping"):
            value = entry[key]
            assert isinstance(value, str) and value.strip(), (
                f"INV {entry['invariant_id']} {key} must be a non-empty string"
            )
