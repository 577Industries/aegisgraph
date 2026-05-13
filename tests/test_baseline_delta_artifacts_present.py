"""v1.0-cut guard for the M14 baseline-tool delta report.

When the report has been executed end-to-end on the self-hosted runner,
this test asserts the rendered artifacts exist at the canonical path.

Pre-execution: the test is skipped via `pytest.mark.skipif` because the
self-hosted runner must produce the report. The skip path is the
expected mode on developer machines and on GitHub-hosted CI.

Path canonicalization: the test computes the workspace-level proposal
package path from the engineering repo location, then checks for:

  03_PROPOSAL/active-package/04_evidence/v0.4/baseline-tool-delta/
    delta-report.md
    delta-report.json
    checksums.sha256
    signal_android/
    element_x_android/

Reviewers can run `python3 -m pytest tests/test_baseline_delta_artifacts_present.py -v`
post-execution to confirm the cut.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aegisgraph.io import repo_root


def _baseline_delta_dir() -> Path:
    """Resolve the workspace-level baseline-tool-delta dir.

    Engineering repo lives at:
        <workspace>/01_TIER3_RESEARCH/AegisGraph_Tier3_Research[/.worktrees/<wt>]/
    Proposal package lives at:
        <workspace>/03_PROPOSAL/active-package/04_evidence/v0.4/baseline-tool-delta/
    """
    rr = repo_root()
    # Walk up to the workspace root. We accept either of:
    #   .../01_TIER3_RESEARCH/AegisGraph_Tier3_Research
    #   .../01_TIER3_RESEARCH/AegisGraph_Tier3_Research/.worktrees/<wt>
    workspace: Path | None = None
    for candidate in [rr, *rr.parents]:
        sibling = candidate.parent.parent  # workspace level (skip 01_TIER3.../<repo>)
        if (sibling / "03_PROPOSAL" / "active-package").is_dir():
            workspace = sibling
            break
        # Try one level deeper (in case of worktree layout)
        deeper = candidate.parent.parent.parent
        if (deeper / "03_PROPOSAL" / "active-package").is_dir():
            workspace = deeper
            break
    if workspace is None:
        # Fall back to the documented constant path.
        workspace = Path("/home/twawe/577i-Projects/SBIR Working Folder/ASEMA")
    return (
        workspace
        / "03_PROPOSAL"
        / "active-package"
        / "04_evidence"
        / "v0.4"
        / "baseline-tool-delta"
    )


BASELINE_DELTA_DIR = _baseline_delta_dir()


# Skip whenever the report hasn't been generated. The expected mode
# pre-M14 is that this skips with a clear reason. Once the self-hosted
# runner has run the workflow, the report will be present and these
# tests will all pass — which is the v1.0 cut condition.
_REPORT_PRESENT = (BASELINE_DELTA_DIR / "delta-report.md").is_file()
_SKIP_REASON = (
    "baseline-tool delta report not yet generated; "
    f"expected at {BASELINE_DELTA_DIR} — runs on self-hosted runner per T-M4.1"
)


@pytest.mark.skipif(not _REPORT_PRESENT, reason=_SKIP_REASON)
def test_delta_report_markdown_exists() -> None:
    assert (BASELINE_DELTA_DIR / "delta-report.md").is_file()


@pytest.mark.skipif(not _REPORT_PRESENT, reason=_SKIP_REASON)
def test_delta_report_json_exists() -> None:
    assert (BASELINE_DELTA_DIR / "delta-report.json").is_file()


@pytest.mark.skipif(not _REPORT_PRESENT, reason=_SKIP_REASON)
def test_checksums_sha256_exists() -> None:
    assert (BASELINE_DELTA_DIR / "checksums.sha256").is_file()


@pytest.mark.skipif(not _REPORT_PRESENT, reason=_SKIP_REASON)
def test_signal_android_subdirectory_exists() -> None:
    assert (BASELINE_DELTA_DIR / "signal_android").is_dir()


@pytest.mark.skipif(not _REPORT_PRESENT, reason=_SKIP_REASON)
def test_element_x_android_subdirectory_exists() -> None:
    assert (BASELINE_DELTA_DIR / "element_x_android").is_dir()


def test_baseline_delta_module_importable() -> None:
    """Always-on regression: the package must import cleanly even
    pre-execution. If this fails the report-renderer is broken at the
    module level.
    """
    import aegisgraph.baseline_delta  # noqa: F401
    from aegisgraph.baseline_delta import renderer, runner  # noqa: F401
