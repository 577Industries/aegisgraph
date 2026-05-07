"""Tests for aegisgraph.reprochain.build().

The build orchestrator must emit a tool-output-shaped manifest at
reprochain/evidence/build_manifest.json with a status that's one of
the documented values. We don't require the toolchain to be present —
the CI host and the dev host may both be in the
"blocked_pending_toolchain" disposition. What we DO require is that
the manifest is well-formed, that the pinned SHAs match the canonical
source-of-truth file, and that no payload bytes / developer-host
paths leak into the committed evidence.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from aegisgraph.reprochain import (
    LIBWEBP_FIX_SHA,
    LIBWEBP_REPO_URL,
    LIBWEBP_VULN_SHA,
    build,
)


# Manifest statuses that aegisgraph.reprochain.build() may produce.
ACCEPTABLE_STATUSES = frozenset(
    {
        "ready",
        "blocked_pending_toolchain",
        "blocked_pending_submodule",
        "blocked_pending_pin_mismatch",
        "blocked_build_failed",
    }
)


@pytest.fixture
def repo_clone(tmp_path) -> Path:
    """Clone the parts of the repo build() touches into tmp_path. We
    don't need the upstream libwebp submodule for these tests — build()
    is supposed to handle a missing submodule by emitting a
    blocked_pending_submodule status."""
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
    # build.sh must be executable for build() to invoke it as a script.
    # copytree preserves the source's mode, so this only runs when the
    # checked-in script lost its +x bit (e.g. on a Windows clone).
    script = tmp_path / "reprochain" / "build.sh"
    if script.is_file():
        mode = script.stat().st_mode
        owner_exec = 0o100  # S_IXUSR
        if not mode & owner_exec:
            script.chmod(mode | owner_exec)
    return tmp_path


def test_pin_constants_match_commit_pins_md(tmp_path) -> None:
    """The three independent sources for the pinned SHAs must agree.

    aegisgraph/reprochain.py, reprochain/build.sh, and
    reprochain/vendor/libwebp/COMMIT_PINS.md each carry the SHAs.
    Drift among them would silently rebuild a different revision than
    the one the ADR documents. This test enforces that they match.
    """
    here = Path(__file__).resolve().parent.parent
    pins_md = (here / "reprochain" / "vendor" / "libwebp" / "COMMIT_PINS.md").read_text()
    build_sh = (here / "reprochain" / "build.sh").read_text()

    assert LIBWEBP_VULN_SHA in pins_md, "vuln SHA missing from COMMIT_PINS.md"
    assert LIBWEBP_FIX_SHA in pins_md, "fix SHA missing from COMMIT_PINS.md"
    assert LIBWEBP_VULN_SHA in build_sh, "vuln SHA missing from build.sh"
    assert LIBWEBP_FIX_SHA in build_sh, "fix SHA missing from build.sh"
    assert LIBWEBP_REPO_URL in pins_md
    # Both must be 40-char hex.
    assert re.fullmatch(r"[0-9a-f]{40}", LIBWEBP_VULN_SHA)
    assert re.fullmatch(r"[0-9a-f]{40}", LIBWEBP_FIX_SHA)


def test_build_emits_well_formed_manifest(repo_clone: Path) -> None:
    """build() always writes build_manifest.json with the required
    fields, regardless of whether the toolchain is available."""
    manifest = build(repo_clone)
    out_path = repo_clone / "reprochain" / "evidence" / "build_manifest.json"
    assert out_path.is_file(), "build_manifest.json was not written"

    on_disk = json.loads(out_path.read_text())
    # The returned dict and the on-disk file must match (build() is
    # write-then-return).
    assert on_disk == manifest

    # Tool-output schema essentials.
    assert manifest["tool_output_type"] == "reprochain_build_manifest"
    assert manifest["version"] == "v1.0"
    assert manifest["safety_posture"] == "private_by_default"
    assert manifest["library"] == "libwebp"

    # Pins must echo the canonical SHAs verbatim.
    assert manifest["pins"]["vulnerable"]["sha"] == LIBWEBP_VULN_SHA
    assert manifest["pins"]["fixed"]["sha"] == LIBWEBP_FIX_SHA

    # Status must be one of the documented values.
    assert manifest["status"] in ACCEPTABLE_STATUSES, manifest["status"]


def test_build_status_ready_requires_artifacts_on_disk(repo_clone: Path) -> None:
    """When status is 'ready' the artifact-present flags must all be
    true and the SHA-256 hashes must be populated. If status is one of
    the 'blocked_*' values the artifact-present flags must all be
    false (the binaries were never built).
    """
    manifest = build(repo_clone)
    if manifest["status"] == "ready":
        assert all(manifest["artifacts_present"].values()), manifest["artifacts_present"]
        # Hashes are only populated for binaries (not archives).
        sha = manifest.get("harness_artifact_sha256", {})
        assert "vuln_binary" in sha and "fix_binary" in sha
        for name, value in sha.items():
            assert re.fullmatch(r"[0-9a-f]{64}", value), (name, value)
    else:
        # blocked_* — artifacts must NOT be present.
        assert not any(manifest["artifacts_present"].values()), manifest["artifacts_present"]


def test_build_manifest_does_not_leak_developer_host_paths(repo_clone: Path) -> None:
    """The committed manifest's 'detail' field must not contain the
    developer's home directory path. This is the integration-stream
    safety contract: any string that lands in committed evidence
    flows through _redact_path() first.
    """
    manifest = build(repo_clone)
    detail = str(manifest.get("detail", ""))
    home = str(Path.home())
    assert home not in detail, f"detail leaked $HOME ({home}): {detail!r}"
    # Absolute path of the repo clone itself must also not appear.
    assert str(repo_clone) not in detail
