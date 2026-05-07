"""Phase 1 reproducibility: extraction output is byte-identical across runs.

`generated_at` is a fixed constant (`STATIC_GENERATED_AT`) so timestamps
don't introduce drift. Everything else — record_hash, evidence_refs,
node ordering — must hash to the same bytes when run twice in a tmpdir.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from aegisgraph.extraction import run_extract


def _hash_extraction_outputs(root: Path) -> dict[str, str]:
    """Return {relpath: sha256} for every committed extraction output."""
    out: dict[str, str] = {}
    base = root / "extraction" / "output"
    for path in sorted(base.rglob("*.json")):
        rel = str(path.relative_to(root))
        # Skip raw outputs and codeql DB (gitignored, not part of the
        # reproducibility contract — they live alongside but aren't shipped).
        if "/raw/" in rel or "/codeql-db/" in rel:
            continue
        # mobsf-results.json and manifest-analysis.json are also gitignored;
        # reproduce-byte-stability covers committed artifacts (graph.json,
        # coverage.json, manifest.json).
        if rel.endswith("manifest-analysis.json") or rel.endswith("mobsf-results.json"):
            continue
        out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def test_run_extract_is_byte_stable_across_runs(tmp_path: Path) -> None:
    shutil.copytree("schema", tmp_path / "schema")

    run_extract(tmp_path)
    first = _hash_extraction_outputs(tmp_path)

    run_extract(tmp_path)
    second = _hash_extraction_outputs(tmp_path)

    assert first, "first run produced no committed extraction outputs"
    assert first == second, (
        "extraction output is not byte-stable across runs.\n"
        f"first  = {first}\n"
        f"second = {second}"
    )


def test_run_extract_is_byte_stable_across_separate_tmpdirs(tmp_path_factory) -> None:
    """Run extraction in two independent tmpdirs and verify the outputs
    match. This guards against a class of bugs where the first run is
    deterministic on a fresh disk but the *second* run is contaminated by
    leftover state from a prior run.
    """
    a = tmp_path_factory.mktemp("first")
    b = tmp_path_factory.mktemp("second")
    shutil.copytree("schema", a / "schema")
    shutil.copytree("schema", b / "schema")

    run_extract(a)
    run_extract(b)

    h_a = _hash_extraction_outputs(a)
    h_b = _hash_extraction_outputs(b)

    # Each set must be non-empty and equal modulo the tmpdir prefix.
    assert h_a and h_b
    keys_a = sorted(h_a.keys())
    keys_b = sorted(h_b.keys())
    assert keys_a == keys_b, f"different output sets: {keys_a} vs {keys_b}"
    for k in keys_a:
        assert h_a[k] == h_b[k], f"hash mismatch for {k}: {h_a[k]} != {h_b[k]}"
