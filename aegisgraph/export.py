from __future__ import annotations

from pathlib import Path
from typing import Any

from .constants import STATIC_GENERATED_AT
from .io import load_json, sha256_file, write_json
from .validation import validate_repo


PRIVATE_EXPORT_INPUTS = [
    "tooling-versions.json",
    "validation-report.json",
    "extraction/output/manifest.json",
    "extraction/output/signal/graph.json",
    "extraction/output/element-x/graph.json",
    "reprochain/evidence/build_manifest.json",
    "reprochain/evidence/run_status.json",
    "reprochain/evidence/mapping.json",
    "polydiff/regression/report.json",
    "polydiff/evidence/regression.evidence.json",
    "smabench/results/latest/results.json",
]

PUBLIC_ALLOWED_INPUTS = [
    "extraction/output/manifest.json",
    "polydiff/regression/report.json",
    "smabench/results/latest/results.json",
    "validation-report.json",
]


def _existing_artifacts(root: Path, relpaths: list[str]) -> list[dict[str, Any]]:
    artifacts = []
    for relpath in relpaths:
        path = root / relpath
        if path.exists() and path.is_file():
            artifacts.append({"path": relpath, "sha256": sha256_file(path)})
    return artifacts


def export_private(root: Path) -> dict[str, Any]:
    validation = validate_repo(root)
    artifacts = _existing_artifacts(root, PRIVATE_EXPORT_INPUTS)
    manifest = {
        "tool_output_type": "private_submission_export",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "release_boundary": "private DARPA/ASEMA submission candidate; not public sanitized output",
        "validation_status": validation["status"],
        "artifacts": artifacts,
        "excluded": [
            "reprochain/corpora-private/**",
            "raw target source trees",
            "raw scanner dumps",
            "credentials or live dynamic traces",
        ],
    }
    write_json(root / "exports" / "private-submission" / "manifest.json", manifest)
    return manifest


def _sanitize_polydiff_report(root: Path) -> dict[str, Any] | None:
    source = root / "polydiff" / "regression" / "report.json"
    if not source.exists():
        return None
    report = load_json(source)
    sanitized = dict(report)
    sanitized["safety_posture"] = "sanitized_candidate"
    for vector in sanitized.get("fact_vectors", []):
        vector.pop("input_raw", None)
    return sanitized


def export_public_sanitized(root: Path) -> dict[str, Any]:
    validation = validate_repo(root)
    public_dir = root / "exports" / "public-sanitized"
    sanitized_polydiff = _sanitize_polydiff_report(root)
    if sanitized_polydiff is not None:
        write_json(public_dir / "polydiff_regression_report.sanitized.json", sanitized_polydiff)

    artifacts = _existing_artifacts(root, PUBLIC_ALLOWED_INPUTS)
    if (public_dir / "polydiff_regression_report.sanitized.json").exists():
        artifacts.append(
            {
                "path": "exports/public-sanitized/polydiff_regression_report.sanitized.json",
                "sha256": sha256_file(public_dir / "polydiff_regression_report.sanitized.json"),
            }
        )
    manifest = {
        "tool_output_type": "public_sanitized_export",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "sanitized_candidate",
        "release_authorized": False,
        "release_note": "Human approval is still required before replacing or supplementing 02_PUBLIC_RELEASE/ASEMA_Public_GitHub_Artifacts.",
        "validation_status": validation["status"],
        "artifacts": artifacts,
        "excluded": [
            "exports/private-submission/**",
            "reprochain/corpora-private/**",
            "undisclosed findings",
            "raw target source",
            "raw scanner dumps",
            "credentials",
            "live dynamic traces",
        ],
    }
    write_json(public_dir / "manifest.json", manifest)
    return manifest
