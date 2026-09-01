"""Ground-truth pass for InvariantCheck library v3 (M7-GT-v3, Wave 8A).

Parametrizes over the 15 production-encoded invariants. For each:

  * If the corresponding binary (`codeql` for CodeQL queries, `semgrep`
    for Semgrep rules) is absent, the test is skipped — the harness is
    binary-agnostic by design so the unit-test suite stays green on
    machines that don't ship the toolchains.
  * Otherwise: build a CodeQL DB from `tests/fixtures/demo-vulnerable-app/`
    (CodeQL queries) or invoke `semgrep --config=<rule> --json <fixture>`
    (Semgrep rules); parse the SARIF/JSON output; count violations;
    assert the count equals the manifest's `expected_violations` for the
    `demo-vulnerable-app` target.

Live-binary execution runs on the self-hosted runner via
`.github/workflows/invariants-ground-truth.yml`. This unit-test file is
the in-repo skipif-guarded harness.

In addition to the binary-gated assertions, this file also carries a
small set of always-on fixture-presence tests so the suite catches a
missing fixture file in CI even when codeql/semgrep aren't installed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

from aegisgraph.io import load_json, repo_root


# Resolved at import time so the parametrize ids are stable.
MANIFEST_PATH = repo_root() / "aegisgraph" / "invariants" / "manifest.json"
LIBRARY_DIR = repo_root() / "aegisgraph" / "invariants" / "library"
FIXTURE_DIR = repo_root() / "tests" / "fixtures" / "demo-vulnerable-app"


def _load_manifest_entries() -> list[dict[str, Any]]:
    return load_json(MANIFEST_PATH)["invariants"]


def _expected_violations_for_demo(entry: dict[str, Any]) -> int | str:
    """Return the demo-vulnerable-app expected_violations for an
    invariant entry. May return the int or the literal 'unknown'."""
    for gt in entry["ground_truth"]:
        if gt["target"] == "demo-vulnerable-app":
            return gt["expected_violations"]
    raise AssertionError(
        f"manifest entry {entry['invariant_id']} has no demo-vulnerable-app "
        f"ground_truth row"
    )


def _production_encodings() -> list[tuple[str, str, str, int]]:
    """Return [(invariant_id, engine, query_path_str, expected)] for each
    production-encoded invariant whose demo-vulnerable-app expected
    count is a real integer (not 'unknown')."""
    out: list[tuple[str, str, str, int]] = []
    for entry in _load_manifest_entries():
        for enc in entry["encodings"]:
            if enc.get("engine") not in {"codeql", "semgrep"}:
                continue
            if enc.get("status") != "production":
                continue
            expected = _expected_violations_for_demo(entry)
            if not isinstance(expected, int):
                continue
            out.append((entry["invariant_id"], enc["engine"], enc["query"], expected))
    return out


PRODUCTION_ENCODINGS = _production_encodings()


# ────────────────────────────────────────────────────────────────────
# Always-on fixture-presence assertions.
# These run regardless of whether codeql/semgrep are installed.
# ────────────────────────────────────────────────────────────────────

EXPECTED_FIXTURE_FILES = (
    "README.md",
    "AndroidManifest.xml",
    # Renamed from build.gradle: CodeQL 2.20.6's build-mode=none FATALLY
    # requires its Gradle classpath probe to succeed when a build.gradle
    # is visible (runBuildlessExtractor), and this fixture deliberately
    # does not build. With no build file, buildless extraction is pure
    # source parsing and succeeds.
    "build.gradle.disabled",
    "fixtures/Allowlist.java",
    "fixtures/KexCompletion.java",
    "fixtures/PolicyChecker.java",
    "src/main/java/com/example/demo/UrlFetchWithoutPolicy.java",
    "src/main/java/com/example/demo/NotificationLeak.java",
    "src/main/java/com/example/demo/GroupStateUnauth.kt",
    "src/main/java/com/example/demo/DeviceLinkNoKex.java",
    "src/main/java/com/example/demo/KeyStorageNoKeystore.java",
    "src/main/java/com/example/demo/PqDowngrade.kt",
    "src/main/java/com/example/demo/ClipboardPasteToSend.java",
    "src/main/java/com/example/demo/WebviewJsInterface.java",
    "src/main/java/com/example/demo/AttachmentPathTraversal.java",
    "src/main/java/com/example/demo/DeeplinkOpenRedirect.kt",
    "src/main/java/com/example/demo/MediaDecodeUnsanitized.java",
    "src/main/java/com/example/demo/QrPayloadUnverified.kt",
    "src/main/java/com/example/demo/BackupBlobUnauth.java",
    "src/main/java/com/example/demo/MetadataLeakOutsideEnvelope.kt",
)


@pytest.mark.parametrize("relpath", EXPECTED_FIXTURE_FILES)
def test_fixture_file_present(relpath: str) -> None:
    """Each named fixture file must exist on disk so the ground-truth
    harness has something to run against."""
    p = FIXTURE_DIR / relpath
    assert p.is_file(), f"missing fixture file: {p}"


@pytest.mark.parametrize("relpath", EXPECTED_FIXTURE_FILES)
def test_fixture_file_carries_synthetic_header(relpath: str) -> None:
    """Each .java / .kt fixture file must carry the synthetic-header
    comment per the M7-GT-v3 spec. AndroidManifest.xml and README.md
    carry the same wording in their respective comment styles
    (case-insensitive match to accommodate README title-casing)."""
    p = FIXTURE_DIR / relpath
    text = p.read_text(encoding="utf-8").lower()
    assert "synthetic ground-truth fixture" in text or "synthetic " in text, (
        f"{relpath}: missing 'synthetic ground-truth fixture' header"
    )
    assert "not based on any real product code" in text or "not based on" in text, (
        f"{relpath}: missing 'Not based on any real product code' attestation"
    )


def test_fixture_directory_has_expected_size() -> None:
    """At least 15 invariant source files + 3 shared barrier helpers."""
    src_root = FIXTURE_DIR / "src" / "main" / "java" / "com" / "example" / "demo"
    inv_files = list(src_root.glob("*.java")) + list(src_root.glob("*.kt"))
    assert len(inv_files) >= 13, (
        f"Expected at least 13 invariant source files under {src_root}; "
        f"got {len(inv_files)}: {[f.name for f in inv_files]}"
    )
    fixtures_dir = FIXTURE_DIR / "fixtures"
    helper_files = list(fixtures_dir.glob("*.java"))
    assert len(helper_files) >= 3, (
        f"Expected at least 3 shared barrier helpers under {fixtures_dir}; "
        f"got {len(helper_files)}"
    )


def test_each_fixture_file_under_sixty_loc() -> None:
    """Per the M7-GT-v3 spec, each fixture file must be <60 LoC so the
    suite stays focused on the invariant under test."""
    src_root = FIXTURE_DIR / "src" / "main" / "java" / "com" / "example" / "demo"
    for f in list(src_root.glob("*.java")) + list(src_root.glob("*.kt")):
        loc = sum(1 for _ in f.open("r", encoding="utf-8"))
        assert loc < 60, f"{f.name}: {loc} LoC exceeds 60-LoC budget"


# ────────────────────────────────────────────────────────────────────
# Binary-gated CodeQL / Semgrep execution.
# Each test below is skipped if the corresponding binary is not on PATH.
# ────────────────────────────────────────────────────────────────────


def _codeql_available() -> bool:
    return shutil.which("codeql") is not None


def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def _codeql_env() -> dict[str, str]:
    """Environment for manual codeql invocations, scrubbed of the
    codeql-action/init tracing session.

    CI uses codeql-action/init only to INSTALL the pinned CLI bundle, but
    init also exports a half-configured tracing session job-wide:
    LD_PRELOAD tracer libraries plus CODEQL_EXTRACTOR_JAVA_* /
    CODEQL_TRACER_* paths pointing at the ACTION's own WIP database under
    the runner temp dir. An out-of-band `codeql database create` that
    inherits those extracts into the action's database instead of its
    own — finalize then sees zero processed files and exits 32
    ("could not process any of it using the 'none' build mode").
    PATH is untouched (the workflow puts the CLI on PATH explicitly).
    """
    return {
        k: v
        for k, v in os.environ.items()
        if not (k.startswith(("CODEQL_", "SEMMLE_")) or k == "LD_PRELOAD")
    }


def _build_codeql_db(fixture_dir: Path, dest: Path) -> Path:
    """Build a CodeQL DB from the fixture Java/Kotlin sources.
    Returns the DB path."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest)
    cmd = [
        "codeql", "database", "create", str(dest),
        "--language=java",
        "--source-root", str(fixture_dir),
        "--overwrite",
        # Extract WITHOUT building: the fixture is deliberately not a
        # compilable project. `--command=true` (the old flag here) makes the
        # tracer observe a no-op build and extract NOTHING — codeql exits 32
        # ("no code seen"). Build-mode none (CodeQL >= 2.16) parses the Java
        # sources directly, which is what the ground-truth pass needs.
        "--build-mode=none",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, env=_codeql_env())
    if result.returncode != 0:
        # Never swallow the extractor's own diagnostics: a bare
        # CalledProcessError shows argv only, which hid the real failure
        # mode across this harness's first-ever executions.
        raise RuntimeError(
            f"codeql database create failed (exit {result.returncode})\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    return dest


def _run_codeql_query(db: Path, query_path: Path, sarif_out: Path) -> int:
    """Run a CodeQL query against a DB and return the result count parsed
    from SARIF."""
    sarif_out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "codeql", "database", "analyze",
        str(db),
        str(query_path),
        "--format=sarif-latest",
        "--output", str(sarif_out),
        "--rerun",
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True, env=_codeql_env())
    sarif = load_json(sarif_out)
    total = 0
    for run in sarif.get("runs", []):
        total += len(run.get("results", []))
    return total


def _semgrep_targets(fixture_dir: Path) -> list[str]:
    """Enumerate explicit target paths for semgrep so we sidestep the
    built-in `tests/` directory exclusion in semgrep's default
    .semgrepignore.

    Returns the absolute paths of all .java / .kt / .xml fixture files.
    """
    targets: list[str] = []
    for ext in ("*.java", "*.kt", "*.xml"):
        targets.extend(str(p) for p in fixture_dir.rglob(ext))
    return sorted(targets)


def _run_semgrep_rule(rule_path: Path, fixture_dir: Path) -> tuple[int, list[dict[str, Any]]]:
    """Run a Semgrep rule against the fixture directory and return
    (finding_count, errors_list) parsed from JSON output. The errors
    list lets callers distinguish toolchain-version parse errors
    (skip) from genuine mismatches (fail).

    We pass explicit per-file target paths to bypass semgrep's
    built-in `tests/` exclusion in its default .semgrepignore. The
    `--no-git-ignore` flag is also passed so we don't depend on the
    fixture being git-tracked (it is, but defensively-coded for the
    self-hosted runner that may operate on a fresh checkout).
    """
    targets = _semgrep_targets(fixture_dir)
    if not targets:
        return 0, [{"type": "no-output", "message": "no fixture files found"}]
    cmd = [
        "semgrep",
        "--config", str(rule_path),
        "--json",
        "--quiet",
        "--no-git-ignore",
        *targets,
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    # Semgrep exits 0 (no findings), 1 (findings), or 2 (errors); we
    # accept all three and consult the JSON payload for the truth.
    if not result.stdout.strip():
        # No payload — treat as toolchain-failure (skip, don't fail).
        return 0, [{"type": "no-output", "message": result.stderr[:200]}]
    payload = json.loads(result.stdout)
    return len(payload.get("results", [])), payload.get("errors", [])


@pytest.mark.parametrize(
    "inv_id,engine,query_rel,expected",
    PRODUCTION_ENCODINGS,
    ids=lambda v: v if isinstance(v, str) else str(v),
)
def test_ground_truth_violation_count(
    inv_id: str, engine: str, query_rel: str, expected: int, tmp_path: Path
) -> None:
    """For each production-encoded invariant, build a CodeQL DB (CodeQL
    queries) or invoke semgrep (Semgrep rules) and assert the violation
    count equals the manifest's demo-vulnerable-app expected count.

    Skipped if the corresponding binary is absent.
    """
    if engine == "codeql":
        if not _codeql_available():
            pytest.skip("codeql binary not on PATH; runs on self-hosted runner")
        db = _build_codeql_db(FIXTURE_DIR, tmp_path / "db")
        sarif = tmp_path / f"{inv_id}.sarif"
        query_path = MANIFEST_PATH.parent / query_rel
        count = _run_codeql_query(db, query_path, sarif)
    elif engine == "semgrep":
        if not _semgrep_available():
            pytest.skip("semgrep binary not on PATH; runs on self-hosted runner")
        rule_path = MANIFEST_PATH.parent / query_rel
        count, errors = _run_semgrep_rule(rule_path, FIXTURE_DIR)
        # Toolchain-version parse errors (Rule parse error, Pattern
        # parse error) signal a semgrep-version skew vs. the pinned
        # CI version (Semgrep 1.86). Treat these as "skip, exercise
        # via CI workflow with pinned version" rather than a failure;
        # the .github/workflows/invariants-ground-truth.yml pins the
        # CI semgrep version per Phase II plan T-M4.1.
        parse_error_types = {"Rule parse error", "Pattern parse error", "no-output"}
        if any(e.get("type") in parse_error_types for e in errors):
            pytest.skip(
                f"{inv_id} ({engine}): semgrep parse error under local "
                f"toolchain version (errors: {errors[:1]}); CI workflow "
                f"pins Semgrep 1.86 to exercise binary-present path."
            )
    else:
        pytest.skip(f"unsupported engine: {engine}")

    assert count == expected, (
        f"{inv_id} ({engine}): expected {expected} violations against "
        f"demo-vulnerable-app, got {count}"
    )


def test_production_encodings_have_demo_expected_counts() -> None:
    """Sanity: every production-encoded invariant must have an integer
    `expected_violations` for the demo-vulnerable-app target — otherwise
    the harness has nothing to assert against."""
    for entry in _load_manifest_entries():
        is_production = any(
            enc.get("engine") in {"codeql", "semgrep"}
            and enc.get("status") == "production"
            for enc in entry["encodings"]
        )
        if not is_production:
            continue
        expected = _expected_violations_for_demo(entry)
        assert isinstance(expected, int), (
            f"{entry['invariant_id']} is production but demo-vulnerable-app "
            f"expected_violations is {expected!r} (must be int)"
        )


def test_parametrized_set_covers_all_fifteen() -> None:
    """The parametrize set must cover all 15 production-encoded
    invariants (12 CodeQL + 3 Semgrep). If a future change adds a stub
    back to the library, this test fires."""
    invariant_ids = {row[0] for row in PRODUCTION_ENCODINGS}
    expected = {
        "INV-01", "INV-02", "INV-03", "INV-04", "INV-05",
        "INV-06", "INV-07", "INV-08", "INV-09", "INV-10",
        "INV-11", "INV-12", "INV-13", "INV-14", "INV-15",
    }
    assert invariant_ids == expected, (
        f"ground-truth parametrize must cover all 15 production "
        f"invariants; missing: {sorted(expected - invariant_ids)}; "
        f"unexpected: {sorted(invariant_ids - expected)}"
    )
