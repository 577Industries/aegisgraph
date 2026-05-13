"""Wave 9B (M9.2) — validation_evidence integrity test.

Asserts that the AG-XSMA-VALIDATED-SIG-GP-001-ELX record's
`validation_evidence` block:

  * `kind == "harnessgen_build"` (we wrap the pre-existing Element X
    JVM harness; no new template was generated for this validation);
  * `harness_path` resolves to an existing file under reprochain/;
  * `harness_artifact_sha256` matches the actual SHA-256 of that file
    on disk (the SHA must be byte-exact for forgery-evident linkage to
    the harness artifact).

This is the test that catches drift: if the harness Java source is
edited but the validation record's SHA is not regenerated, this fails
and the worktree blocks promotion.
"""

from __future__ import annotations

from aegisgraph.crosssma.validation.elementx_linkpreview_xsma import (
    validated_record_path,
)
from aegisgraph.io import load_json, repo_root, sha256_file


def _load_validated_record() -> dict:
    return load_json(validated_record_path())


def test_validation_evidence_kind_is_harnessgen_build() -> None:
    record = _load_validated_record()
    ve = record["validation_evidence"]
    assert ve["kind"] == "harnessgen_build", (
        f"validation_evidence.kind is {ve['kind']!r}; expected "
        "harnessgen_build (the only kind this Wave 9B record claims)"
    )


def test_validation_evidence_build_status_success() -> None:
    """The Element X harness ships with a build.gradle and a syntactically
    valid Java file; build_status: success is the honest read of the
    artifact-presence check (we did not generate a fresh harness)."""
    record = _load_validated_record()
    assert record["validation_evidence"]["build_status"] == "success"


def test_validation_evidence_harness_path_exists_on_disk() -> None:
    record = _load_validated_record()
    rel = record["validation_evidence"]["harness_path"]
    assert rel, "harness_path is empty on validation record"
    full = repo_root() / rel
    assert full.exists(), (
        f"harness_path {rel!r} does not resolve to an existing file at "
        f"{full}"
    )
    assert full.is_file(), f"harness_path {full} is not a regular file"


def test_validation_evidence_harness_sha256_matches_disk() -> None:
    """SHA-256 on the record must match a fresh hash of the on-disk
    file; otherwise either the file was edited without updating the
    record, or the record was forged."""
    record = _load_validated_record()
    rel = record["validation_evidence"]["harness_path"]
    full = repo_root() / rel
    actual = sha256_file(full)
    declared = record["validation_evidence"]["harness_artifact_sha256"]
    assert declared == actual, (
        f"harness_artifact_sha256 drift: record declares {declared!r}, "
        f"disk SHA-256 is {actual!r}"
    )


def test_validation_evidence_references_test_artifact() -> None:
    """build_evidence_ref points at the harness-artifact-presence test
    in the harnessgen suite — reviewers can rerun that test to verify
    the harness exists and the SHA matches."""
    record = _load_validated_record()
    ref = record["validation_evidence"]["build_evidence_ref"]
    assert ref, "build_evidence_ref empty"
    # Honest constraint: the reference is either a path to a test file
    # in the repo, or a test id in pytest-collection form. We accept
    # either, but for a path form it must exist on disk.
    if ref.endswith(".py") and "/" in ref:
        full = repo_root() / ref
        assert full.exists(), (
            f"build_evidence_ref {ref!r} is path-shaped but does not "
            f"exist at {full}"
        )
