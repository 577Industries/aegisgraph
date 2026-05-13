"""Smoke test: aegisgraph.invariants and its submodules import cleanly.

This is the M3.3 sanity check that the InvariantCheck (Engine 3) library
scaffold exists and is importable. It does not exercise runtime behavior
(other tests do that) — only that:

  * `aegisgraph.invariants` is importable;
  * the manifest file is present at the expected path;
  * the SARIF consolidator and the two runner modules are importable;
  * the library directories contain the v0 query files for the 5 invariants
    we ship at M3.3 (INV-01, INV-07, INV-09, INV-11, INV-13).

If this test starts failing in the future, the most likely cause is a
move/rename of one of the M3.3 scaffold files; treat the failure as a
naming-contract regression, not a flaky test.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from aegisgraph.io import repo_root


def test_aegisgraph_invariants_package_imports() -> None:
    module = importlib.import_module("aegisgraph.invariants")
    assert module is not None


def test_sarif_consolidator_importable() -> None:
    module = importlib.import_module("aegisgraph.invariants.runner.sarif_consolidator")
    assert hasattr(module, "consolidate_sarif")


def test_codeql_runner_importable() -> None:
    module = importlib.import_module("aegisgraph.invariants.runner.codeql_runner")
    assert hasattr(module, "run_codeql")


def test_semgrep_runner_importable() -> None:
    module = importlib.import_module("aegisgraph.invariants.runner.semgrep_runner")
    assert hasattr(module, "run_semgrep")


def test_manifest_file_present() -> None:
    manifest_path = repo_root() / "aegisgraph" / "invariants" / "manifest.json"
    assert manifest_path.is_file(), f"missing manifest.json at {manifest_path}"


@pytest.mark.parametrize(
    "relative_path",
    [
        # Pack metadata.
        "aegisgraph/invariants/library/codeql/qlpack.yml",
        # M3.3 baseline (5).
        "aegisgraph/invariants/library/codeql/01_url_fetch_without_policy.ql",
        "aegisgraph/invariants/library/codeql/11_deeplink_open_redirect.ql",
        "aegisgraph/invariants/library/codeql/13_qr_payload_unverified_binding.ql",
        "aegisgraph/invariants/library/semgrep/07_intent_filter_implicit_export.yaml",
        "aegisgraph/invariants/library/semgrep/09_webview_jsinterface_addjavascript.yaml",
        # M5.3 additions (10) — 9 CodeQL + 1 Semgrep.
        "aegisgraph/invariants/library/codeql/02_notification_leak.ql",
        "aegisgraph/invariants/library/codeql/03_group_state_unauth.ql",
        "aegisgraph/invariants/library/codeql/04_device_link_no_kex.ql",
        "aegisgraph/invariants/library/codeql/05_key_storage_no_keystore.ql",
        "aegisgraph/invariants/library/codeql/06_pq_downgrade.ql",
        "aegisgraph/invariants/library/codeql/10_attachment_path_traversal.ql",
        "aegisgraph/invariants/library/codeql/12_media_decode_unsanitized.ql",
        "aegisgraph/invariants/library/codeql/14_backup_blob_unauthenticated.ql",
        "aegisgraph/invariants/library/codeql/15_metadata_leak_outside_envelope.ql",
        "aegisgraph/invariants/library/semgrep/08_clipboard_paste_to_send.yaml",
    ],
)
def test_library_files_present(relative_path: str) -> None:
    path: Path = repo_root() / relative_path
    assert path.is_file(), f"missing library file: {relative_path}"
    # The plan calls for non-empty content in both stubs (comment block describing
    # intent) and fully-written queries. Either way, an empty file is a regression.
    assert path.stat().st_size > 0, f"library file is empty: {relative_path}"
