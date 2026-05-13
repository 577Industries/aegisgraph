"""Orchestrator entry-point for the baseline-tool delta report.

Invoked by `.github/workflows/baseline-delta.yml` on the self-hosted
runner:

    python3 -m aegisgraph.baseline_delta \
        --output 03_PROPOSAL/active-package/04_evidence/v0.4/baseline-tool-delta

Pure subprocess + file I/O. No live HTTP from this module — all tool
execution is delegated to the per-tool runners which themselves shell
out to CLIs that the Dockerfile pins.

Output tree (locked by tests/test_baseline_delta_artifacts_present.py):

    <output_dir>/
    |-- signal_android/
    |   |-- codeql-findings.json
    |   |-- codeql-coverage.json
    |   |-- semgrep-findings.json
    |   |-- semgrep-coverage.json
    |   |-- mobsf-findings.json  (or MOBSF-LIMITED.md if APK absent)
    |   |-- aegisgraph-findings.json
    |   `-- aegisgraph-coverage.json
    |-- element_x_android/
    |   `-- (same shape)
    |-- delta-report.md
    |-- delta-report.json
    `-- checksums.sha256

Atomicity: checksums.sha256 is regenerated after every full run and
covers all sibling files in the output tree. The runner writes each
finding file with its own deterministic generated_at, so the
sha256sum hashes are stable across re-runs unless a tool's output
actually changes.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ..io import repo_root, sha256_file, write_json, write_text
from . import runner as bdrunner
from .renderer import build_delta_report_payload, render_delta_report_markdown


# Target-key -> output-dir-name mapping. The output tree uses
# underscore-snake spellings while the engineering constants use
# hyphenated keys.
_OUTPUT_DIRS = {
    "signal": "signal_android",
    "element-x": "element_x_android",
}


def _gather_findings_from_envelopes(envelopes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Read each runner's findings_path and aggregate normalized rows."""
    out: list[dict[str, Any]] = []
    for env in envelopes:
        path = env.get("findings_path")
        if not path:
            continue
        p = Path(path)
        if not p.is_file():
            continue
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.extend(payload.get("findings", []))
    return out


def regenerate_checksums(*, output_dir: Path) -> Path:
    """Compute sha256 over every regular file (excluding checksums.sha256
    itself) under `output_dir` and write `checksums.sha256` atomically.

    The format matches `sha256sum -c` conventions: `<hex> <relpath>`.
    """
    checksums_path = output_dir / "checksums.sha256"
    rows: list[str] = []
    for entry in sorted(output_dir.rglob("*")):
        if not entry.is_file():
            continue
        if entry.name == "checksums.sha256":
            continue
        rel = entry.relative_to(output_dir).as_posix()
        digest = sha256_file(entry)
        rows.append(f"{digest}  {rel}")
    write_text(checksums_path, "\n".join(rows) + "\n")
    return checksums_path


def run_full_report(*, output_dir: Path, repo: Path | None = None) -> dict[str, Any]:
    """Top-level orchestrator. Returns the rendered delta payload."""
    repo = repo or repo_root()
    output_dir.mkdir(parents=True, exist_ok=True)

    specs = bdrunner.build_target_specs(repo_root=repo)
    per_tool_envelopes: dict[str, dict[str, dict[str, Any]]] = {}
    target_metadata: dict[str, dict[str, Any]] = {}
    all_envelopes: list[dict[str, Any]] = []

    for spec in specs:
        target_key = spec["target_key"]
        target_out = output_dir / _OUTPUT_DIRS[target_key]
        target_out.mkdir(parents=True, exist_ok=True)

        codeql_env = bdrunner.run_codeql_alone(target=spec, output_dir=target_out)
        semgrep_env = bdrunner.run_semgrep_alone(target=spec, output_dir=target_out)
        mobsf_env = bdrunner.run_mobsf_alone(target=spec, output_dir=target_out)
        ag_env = bdrunner.run_aegisgraph_alone(target=spec, output_dir=target_out)

        all_envelopes.extend([codeql_env, semgrep_env, mobsf_env, ag_env])
        per_tool_envelopes[target_key] = {
            "codeql": codeql_env,
            "semgrep": semgrep_env,
            "mobsf": mobsf_env,
            "aegisgraph": ag_env,
        }
        target_metadata[target_key] = {
            "name": spec["name"],
            "target_id": spec["target_id"],
            "repo_url": spec["repo_url"],
            "commit": spec["commit"],
        }

    findings = _gather_findings_from_envelopes(all_envelopes)
    payload = build_delta_report_payload(
        findings=findings,
        per_tool_envelopes=per_tool_envelopes,
        target_metadata=target_metadata,
    )
    write_json(output_dir / "delta-report.json", payload)
    write_text(output_dir / "delta-report.md", render_delta_report_markdown(report_payload=payload))
    regenerate_checksums(output_dir=output_dir)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegisgraph.baseline_delta")
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for the baseline-tool delta report tree.",
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="Engineering repo root (defaults to aegisgraph.io.repo_root()).",
    )
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve() if args.repo else repo_root()
    output_dir = Path(args.output).resolve()
    run_full_report(output_dir=output_dir, repo=repo)
    print(f"baseline-tool delta report written to {output_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
