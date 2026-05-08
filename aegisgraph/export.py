from __future__ import annotations

import os
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


# The human authorization gate (release_authorized=True) requires BOTH:
#
#   1. AEGISGRAPH_RELEASE_AUTHORIZED=1 set in the calling environment
#      (i.e. an operator deliberately authorized this run), AND
#   2. validator/sanitize_check.py would pass against the rendered
#      exports/public-sanitized/ tree.
#
# Until the validator-export stream lands sanitize_check.py, condition (2)
# is structurally unmet and `release_authorized` MUST stay False. We do
# NOT short-circuit through the env var alone — that would let a careless
# operator bypass the sanitize check.
#
# See docs/decision-log/0011-public-export-human-gate.md.
ENV_RELEASE_AUTHORIZED = "AEGISGRAPH_RELEASE_AUTHORIZED"


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

    # The tool-output schema (schema/tool-output.schema.json) pins
    # `version` to the const "v1.0" so every tool-output document carries
    # the same outer-envelope contract. The polydiff regression report
    # internally evolved to v2.0 (richer fact_vector schema, additive only),
    # but for the sanitized public export we keep the v1.0 envelope so the
    # validator's tool-output schema still matches. The originating
    # internal schema version is preserved as `report_schema_version` so
    # downstream consumers can still distinguish v1 vs v2 fact_vector
    # shapes; structure is unchanged (additive fields keep working under
    # tool-output.schema.json's `additionalProperties: true`).
    if "version" in sanitized:
        sanitized["report_schema_version"] = sanitized["version"]
    sanitized["version"] = "v1.0"

    for vector in sanitized.get("fact_vectors", []):
        vector.pop("input_raw", None)
    return sanitized


def export_public_sanitized(root: Path, *, dry_run: bool = False) -> dict[str, Any]:
    """Build the public-sanitized export manifest.

    This function ALWAYS produces a manifest with `release_authorized=False`
    until the human authorization gate is wired (see deliverable note in
    docs/decision-log/0011-public-export-human-gate.md). Even if an operator
    sets AEGISGRAPH_RELEASE_AUTHORIZED=1, this function will not flip the
    flag because the matching validator/sanitize_check.py module is owned
    by the validator-export stream and has not landed yet. The manifest
    documents the unmet gate explicitly in `release_note`.

    `dry_run=True` runs every read step but does NOT write any file under
    exports/public-sanitized/. The returned manifest is identical to a
    real run; this lets reviewers verify the contents without mutating
    the export tree. This is also the mode CI sanitize-check runs in
    when no human authorization is present.
    """
    validation = validate_repo(root)
    public_dir = root / "exports" / "public-sanitized"
    sanitized_polydiff = _sanitize_polydiff_report(root)
    sanitized_path = public_dir / "polydiff_regression_report.sanitized.json"

    if sanitized_polydiff is not None and not dry_run:
        write_json(sanitized_path, sanitized_polydiff)

    artifacts = _existing_artifacts(root, PUBLIC_ALLOWED_INPUTS)
    if not dry_run and sanitized_path.exists():
        artifacts.append(
            {
                "path": "exports/public-sanitized/polydiff_regression_report.sanitized.json",
                "sha256": sha256_file(sanitized_path),
            }
        )

    # ---- Human authorization gate (deliverable 7) ----
    # This block is intentionally fail-closed. The flag is False unless
    # BOTH (a) env AEGISGRAPH_RELEASE_AUTHORIZED=1 AND (b) the
    # validator-export stream's sanitize_check passes. Today (b) is
    # unwired, so we always emit False with a clear release_note.
    #
    # TODO(validator-export-stream): replace `_sanitize_check_passes`
    # with a real call to validator.sanitize_check. Until then, the
    # function intentionally returns False so this gate cannot trip
    # accidentally.
    env_authorized = os.environ.get(ENV_RELEASE_AUTHORIZED) == "1"
    sanitize_passes = _sanitize_check_passes(root)
    release_authorized = env_authorized and sanitize_passes

    if env_authorized and not sanitize_passes:
        release_note = (
            "AEGISGRAPH_RELEASE_AUTHORIZED=1 set, but validator/sanitize_check.py "
            "is not yet wired or did not pass. release_authorized stays False. "
            "Human approval is still required before replacing or supplementing "
            "02_PUBLIC_RELEASE/ASEMA_Public_GitHub_Artifacts."
        )
    elif not env_authorized:
        release_note = (
            "Human authorization gate not yet wired. release_authorized is False "
            "by default; set AEGISGRAPH_RELEASE_AUTHORIZED=1 AND ensure "
            "validator/sanitize_check.py passes before any public release. See "
            "docs/decision-log/0011-public-export-human-gate.md."
        )
    else:
        release_note = (
            "Both environment authorization and sanitize-check passed; this "
            "manifest may be promoted by the operator after a final human review."
        )

    manifest = {
        "tool_output_type": "public_sanitized_export",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "sanitized_candidate",
        "release_authorized": release_authorized,
        "release_note": release_note,
        "validation_status": validation["status"],
        "dry_run": dry_run,
        "artifacts": artifacts,
        # The list of intentionally-excluded surfaces lives in a sibling
        # EXCLUSIONS.md file; embedding it here would make the manifest
        # self-referential to sanitize-check (e.g. the strings
        # "private-submission" and "corpora-private" would trip path/content
        # rules). EXCLUSIONS.md is allowlisted by validator/sanitize_check.py
        # for that exact reason: the document by design names the things
        # that are excluded.
        "excluded_documentation_at": "EXCLUSIONS.md",
    }

    if not dry_run:
        write_json(public_dir / "manifest.json", manifest)
        _write_exclusions_md(public_dir)
    return manifest


# ---------------------------------------------------------------------------
# EXCLUSIONS.md sibling document
# ---------------------------------------------------------------------------

# These are the surfaces that are deliberately NOT in the public-sanitized
# export. The list is documentation-grade, not machine-consumed; the manifest
# carries `excluded_documentation_at: "EXCLUSIONS.md"` so machines can find
# this file by name.
_EXCLUDED_FROM_PUBLIC: tuple[str, ...] = (
    "exports/private-submission/**",
    "reprochain/corpora-private/**",
    "undisclosed findings",
    "raw target source",
    "raw scanner dumps",
    "credentials",
    "live dynamic traces",
)


def _exclusions_md_body() -> str:
    """Build the EXCLUSIONS.md body. Kept module-private so the doc text and
    the historical excluded-list stay in lock-step."""
    header = (
        "# What's Excluded From This Sanitized Release\n"
        "\n"
        "The following are intentionally NOT in this public-sanitized export:"
    )
    bullets = "\n".join(f"- `{item}`" for item in _EXCLUDED_FROM_PUBLIC)
    return f"{header}\n\n{bullets}\n"


def _write_exclusions_md(public_dir: Path) -> None:
    public_dir.mkdir(parents=True, exist_ok=True)
    (public_dir / "EXCLUSIONS.md").write_text(
        _exclusions_md_body(), encoding="utf-8"
    )


def _sanitize_check_passes(root: Path) -> bool:
    """Real sanitize-check, replaces the integration stub per ADR 0021.

    Lazily imports validator.sanitize_check.is_export_safe so this module
    can still be imported in isolation and so a removed/broken validator
    package fails the gate closed.
    """
    try:
        from validator.sanitize_check import is_export_safe
    except Exception:
        return False
    try:
        return is_export_safe(root / "exports" / "public-sanitized")
    except Exception:
        return False
