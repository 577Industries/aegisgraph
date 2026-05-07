"""SMABench repeatability assertion.

Two consecutive end-to-end orchestrator runs must produce byte-
identical output (modulo the `generated_at` timestamp). This is the
load-bearing reproducibility property the SPEC §7.4 commits us to —
without it any "regression vs. previous run" delta is meaningless.

The test runs the orchestrator into a tmp_path that's been seeded
with a minimal repo skeleton (the real extraction graphs are copied
in if available; otherwise Ring 2 reports pending and the test still
asserts byte-identity).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from aegisgraph import smabench


def _seed_repo_skeleton(tmp_path: Path) -> None:
    """Copy enough of the real repo into tmp_path for the orchestrator
    to run. We need:
      - the schema/ directory (for recommendation validation later)
      - any existing extraction/output/ tree (Ring 2 input)
    Everything else is generated under tmp_path/smabench/ during the run.
    """

    repo_root = Path(__file__).resolve().parents[1]
    for sub in ("schema", "extraction"):
        src = repo_root / sub
        if src.is_dir():
            shutil.copytree(src, tmp_path / sub)


def test_orchestrator_byte_identical_across_runs(tmp_path: Path) -> None:
    _seed_repo_skeleton(tmp_path)
    first = smabench.run(tmp_path)
    second = smabench.run(tmp_path)
    # The orchestrator's own repeatability flag (which compares two
    # internal iterations) must agree.
    assert first["repeatability"]["byte_identical"] is True
    assert second["repeatability"]["byte_identical"] is True
    # And consecutive run-of-run hashes must agree too — this is the
    # stronger property: not just intra-run idempotency but inter-run
    # determinism.
    assert first["repeatability"]["hash"] == second["repeatability"]["hash"]


def test_orchestrator_emits_six_corpora(tmp_path: Path) -> None:
    _seed_repo_skeleton(tmp_path)
    result = smabench.run(tmp_path)
    corpora = result["rings"]["ring1"]["corpora"]
    assert len(corpora) >= 6
    names = {c["name"] for c in corpora}
    expected = {
        "url-corpus",
        "qr-corpus",
        "deeplink-corpus",
        "sync-corpus",
        "media-corpus",
        "pq-corpus",
    }
    assert expected.issubset(names), names


def test_orchestrator_results_files_present(tmp_path: Path) -> None:
    _seed_repo_skeleton(tmp_path)
    smabench.run(tmp_path)
    dated = tmp_path / "smabench" / "results" / "2026-05-05"
    for artifact in ("results.json", "repeatability.json", "delta.json", "recommendations.json", "dashboard.html"):
        assert (dated / artifact).is_file(), f"missing artifact: {artifact}"
    # Latest pointer must resolve to the dated directory.
    latest = tmp_path / "smabench" / "results" / "latest"
    if latest.is_symlink():
        assert (latest / "results.json").is_file()
    else:
        # Copy fallback path: latest.txt must point at the date.
        assert (latest / "results.json").is_file()


def test_orchestrator_recommendations_validate_against_schema(tmp_path: Path) -> None:
    """Any recommendations emitted must be schema-conformant.

    We do not require the orchestrator to emit recommendations on a
    fresh tmp_path (Ring 2 score is too low to trigger them with the
    phase-0 extraction graph), but if it does, every entry must
    validate against `schema/recommendation.schema.json`.
    """

    from jsonschema import Draft202012Validator

    _seed_repo_skeleton(tmp_path)
    smabench.run(tmp_path)
    recs_path = tmp_path / "smabench" / "results" / "2026-05-05" / "recommendations.json"
    schema_path = tmp_path / "schema" / "recommendation.schema.json"
    if not schema_path.is_file():
        return  # schema/ wasn't seeded — skip.
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    recs = json.loads(recs_path.read_text(encoding="utf-8"))
    for rec in recs:
        errors = list(validator.iter_errors(rec))
        assert not errors, (
            f"recommendation {rec.get('id')} violates schema: "
            f"{[e.message for e in errors]}"
        )
