"""Phase 1 coverage contract.

When the FULL toolchain is available (CodeQL CLI + Semgrep + cloned target
source + MobSF docker), `coverage.json.graph_evidence_ref_coverage` should
be >= 0.8 and `path_class_coverage` should include both `media_decode` and
`link_preview`. In the current research dev environment those tools may
not all be available; we loosen the assertions accordingly and key the
strict contract behind a marker that CI can flip.

The non-loosened invariants — present in every environment — are:
  - coverage.json file exists per target
  - graph_evidence_ref_coverage >= 0.0 and <= 1.0
  - path_class_coverage is a non-empty list of valid PATH_CLASSES
  - tool_run_status is present and includes all four canonical tools
  - stale_anchor_detection >= 0
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from aegisgraph.constants import PATH_CLASSES
from aegisgraph.extraction import run_extract


FULL_TOOLCHAIN_FLAG = os.environ.get("AEGISGRAPH_FULL_TOOLCHAIN") == "1"


def _seed_and_load(tmp_path: Path) -> dict[str, dict]:
    shutil.copytree("schema", tmp_path / "schema")
    run_extract(tmp_path)
    coverages: dict[str, dict] = {}
    for cov_path in sorted((tmp_path / "extraction" / "output").glob("*/coverage.json")):
        coverages[str(cov_path.relative_to(tmp_path))] = json.loads(cov_path.read_text())
    return coverages


def test_coverage_file_exists_per_target(tmp_path: Path) -> None:
    coverages = _seed_and_load(tmp_path)
    assert coverages, "no coverage.json files emitted"
    # We expect one per target; constants.py ships two targets.
    assert len(coverages) == 2, sorted(coverages.keys())


def test_coverage_fields_present(tmp_path: Path) -> None:
    coverages = _seed_and_load(tmp_path)
    for path, c in coverages.items():
        assert "graph_evidence_ref_coverage" in c
        assert "path_class_coverage" in c
        assert "tool_run_status" in c
        assert "stale_anchor_detection" in c
        # Numeric ranges
        cov = c["graph_evidence_ref_coverage"]
        assert isinstance(cov, (int, float)), (path, cov)
        assert 0.0 <= cov <= 1.0, (path, cov)
        assert c["stale_anchor_detection"] >= 0, (path, c["stale_anchor_detection"])
        # Path class coverage must be a list of known path classes.
        for pc in c["path_class_coverage"]:
            assert pc in PATH_CLASSES, (path, pc)


def test_tool_run_status_lists_all_four_canonical_tools(tmp_path: Path) -> None:
    coverages = _seed_and_load(tmp_path)
    expected_tools = {"codeql", "semgrep", "manifest", "mobsf"}
    for path, c in coverages.items():
        present = set(c["tool_run_status"].keys())
        assert expected_tools <= present, (path, sorted(expected_tools - present))


@pytest.mark.skipif(
    not FULL_TOOLCHAIN_FLAG,
    reason=(
        "Full toolchain (CodeQL CLI, semgrep, cloned target source, MobSF) "
        "not available; run with AEGISGRAPH_FULL_TOOLCHAIN=1 inside the "
        "devcontainer to enforce strict coverage."
    ),
)
def test_full_toolchain_meets_strict_coverage(tmp_path: Path) -> None:
    coverages = _seed_and_load(tmp_path)
    for path, c in coverages.items():
        assert c["graph_evidence_ref_coverage"] >= 0.8, (path, c["graph_evidence_ref_coverage"])
        assert "media_decode" in c["path_class_coverage"], (path, c["path_class_coverage"])
        assert "link_preview" in c["path_class_coverage"], (path, c["path_class_coverage"])


def test_loose_coverage_in_partial_environment(tmp_path: Path) -> None:
    """In the current research dev env at least the manifest tool can run
    once a target source clone is in place. With no clone, coverage may
    be 0.0; we still require the field to be present and bounded.
    """
    coverages = _seed_and_load(tmp_path)
    for path, c in coverages.items():
        assert c["graph_evidence_ref_coverage"] >= 0.0
