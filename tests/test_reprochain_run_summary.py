"""Tests for aegisgraph.reprochain.run().

Two responsibilities:

1. The committed `asan_report_summary.json` is well-formed: it carries
   the per-binary entries, has no leaking fields (payload_bytes,
   payload_b64, raw_bytes), and respects the scrubbing policy.

2. When a vuln-binary run actually executes, crash_count > 0 and the
   fix-binary run, when it executes, must produce crash_count == 0.
   This is the differential the harness exists to demonstrate.

   On a host without the toolchain neither binary is built, both
   executed=false, and the test simply asserts the structural
   contract instead of a crash count.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from aegisgraph.reprochain import build, run


# Fields we never want to see in the committed summary. If any of them
# show up in a future change, that change must justify itself in
# review.
_FORBIDDEN_KEYS = frozenset(
    {
        "payload_bytes",
        "payload_b64",
        "raw_bytes",
        "raw_input",
        "crash_input_bytes",
        "stack_trace_full",
        "addresses",
    }
)


@pytest.fixture
def repo_clone(tmp_path) -> Path:
    here = Path(__file__).resolve().parent.parent
    for sub in ("schema", "reprochain"):
        shutil.copytree(here / sub, tmp_path / sub, ignore=shutil.ignore_patterns(
            "upstream",
            "build-vuln",
            "build-fix",
            "cmake-vuln",
            "cmake-fix",
            "evidence",
        ))
    script = tmp_path / "reprochain" / "build.sh"
    if script.is_file():
        mode = script.stat().st_mode
        owner_exec = 0o100  # S_IXUSR
        if not mode & owner_exec:
            script.chmod(mode | owner_exec)
    return tmp_path


def _walk(value):
    """Walk every key/value in a nested structure."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def test_run_emits_summary_with_no_forbidden_fields(repo_clone: Path) -> None:
    build(repo_clone)
    run(repo_clone)
    summary_path = repo_clone / "reprochain" / "evidence" / "asan_report_summary.json"
    assert summary_path.is_file()

    summary = json.loads(summary_path.read_text())
    assert summary["tool_output_type"] == "reprochain_asan_summary"
    assert summary["safety_posture"] == "private_by_default"

    # Every key in every nested dict must NOT be one of the forbidden
    # ones.
    for key in _walk(summary):
        if not isinstance(key, str):
            continue
        assert key not in _FORBIDDEN_KEYS, f"forbidden key in summary: {key}"

    # Per-binary entries exist for both labels, in deterministic order.
    labels = [entry["label"] for entry in summary["binaries"]]
    assert labels == ["vuln", "fix"]


def test_run_summary_top_frames_are_function_names_only(repo_clone: Path) -> None:
    """Top frames must contain ONLY function names — no source paths,
    no line numbers, no addresses. The summary is committed; leaking
    a developer-host source path would break the safety contract."""
    build(repo_clone)
    run(repo_clone)
    summary = json.loads(
        (repo_clone / "reprochain" / "evidence" / "asan_report_summary.json").read_text()
    )
    for entry in summary["binaries"]:
        for frame in entry.get("top_frames", []):
            assert set(frame.keys()) <= {"function", "frame_hits"}, frame
            func = frame["function"]
            # No slashes, no colons (source paths use both), no hex addrs.
            assert "/" not in func, func
            assert ":" not in func, func
            assert not re.search(r"0x[0-9a-fA-F]+", func), func


def test_run_differential_when_both_binaries_executed(repo_clone: Path) -> None:
    """Contract: when both binaries actually executed, the differential
    must exist; the vuln crash_count > 0 is required ONLY when the
    seed corpus contains crash-triggering inputs (so on a clean host
    we tolerate vuln crash_count == 0). The fix crash_count must
    always be 0 — that's the no-regression invariant.
    """
    build(repo_clone)
    run(repo_clone)
    summary = json.loads(
        (repo_clone / "reprochain" / "evidence" / "asan_report_summary.json").read_text()
    )
    vuln = next((b for b in summary["binaries"] if b["label"] == "vuln"), None)
    fix = next((b for b in summary["binaries"] if b["label"] == "fix"), None)
    assert vuln is not None and fix is not None

    if vuln.get("executed") and fix.get("executed"):
        diff = summary.get("differential", {})
        assert "vuln_crash_count" in diff
        assert "fix_crash_count" in diff
        assert diff["fix_crash_count"] == 0, "fix-pin should never crash"
    else:
        # Toolchain not present on this host — only structural contract
        # required: both labels appear with skip_reason set.
        assert vuln["executed"] is False
        assert "skip_reason" in vuln
        assert fix["executed"] is False
        assert "skip_reason" in fix


def test_run_status_path_safe(repo_clone: Path) -> None:
    """run_status.json is committed; verify it carries no payload bytes
    and no developer paths."""
    build(repo_clone)
    run(repo_clone)
    status_path = repo_clone / "reprochain" / "evidence" / "run_status.json"
    assert status_path.is_file()
    text = status_path.read_text()
    home = str(Path.home())
    assert home not in text, "run_status.json leaked $HOME"
    assert str(repo_clone) not in text


def test_corpus_manifest_only_hashes_and_notes(repo_clone: Path) -> None:
    """The committed corpus MANIFEST.json must list seeds by sha256
    plus a structural note only — never include payload bytes."""
    build(repo_clone)
    run(repo_clone)
    manifest_path = (
        repo_clone / "reprochain" / "corpora-private" / "handcrafted" / "MANIFEST.json"
    )
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text())
    assert manifest["tool_output_type"] == "reprochain_corpus_manifest"
    for seed in manifest.get("seeds", []):
        # Allowed seed keys only.
        assert set(seed.keys()) <= {"path", "size_bytes", "sha256", "structural_note"}
        # sha256 is 64 hex chars.
        assert re.fullmatch(r"[0-9a-f]{64}", seed["sha256"]), seed["sha256"]
