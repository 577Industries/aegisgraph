"""Hardened evidence validator — same checks as `aegisgraph validate`,
plus a `--non-mutating` mode for third-party verification.

Why this exists separate from `aegisgraph.cli validate`:
  - Third parties (validators, reviewers) who clone the repo need a way
    to *verify* evidence without leaving a write footprint. The
    aegisgraph.validate command writes `validation-report.json` at repo
    root, which mutates a tracked file even if the run is otherwise
    read-only.
  - This module exposes `validate_repo_non_mutating()` that runs the
    exact same `validate_repo()` core but returns the report instead of
    writing it. The CLI surface is `python -m validator.cli validate
    [--non-mutating]`.

The module is also a backwards-compatible drop-in for the previous
single-script `validator/validate_evidence.py` (which was just `aegisgraph
validate`); running it directly still routes to the aegisgraph CLI.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

# Project root one level up from this file. The validator package sits at
# the repo root next to aegisgraph/, so parents[1] is the repo root.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# Env override mirrors the --non-mutating flag. Either is sufficient.
ENV_NON_MUTATING = "AEGISGRAPH_VALIDATOR_NON_MUTATING"


def _non_mutating_requested(non_mutating: bool) -> bool:
    if non_mutating:
        return True
    return os.environ.get(ENV_NON_MUTATING) == "1"


def validate_repo_non_mutating(root: Path) -> dict[str, Any]:
    """Run the full evidence validator against `root` WITHOUT writing to disk.

    Re-implements `aegisgraph.validation.validate_repo` but skips the
    final write_json() call. Keeps the contract identical (same
    schema_errors/record_results/status fields).

    We deliberately do not patch aegisgraph.validation.validate_repo to
    accept a flag: that module is owned by aegisgraph/ and outside our
    scope. Re-implementing here is safer than monkey-patching at runtime.
    """
    # Local imports keep validator package importable even if some
    # aegisgraph submodule has a transient bug, e.g. during a stream
    # rebase. The CLI prints a clear error when imports fail.
    from aegisgraph.io import load_json
    from aegisgraph.schema import (
        check_schema_files,
        validate_against_schema,
        validate_evidence_record,
    )
    from aegisgraph.validation import _records_from_document, evidence_documents

    schema_errors = check_schema_files(root)
    record_results: list[dict[str, Any]] = []
    records_checked = 0
    for path in evidence_documents(root):
        try:
            document = load_json(path)
        except Exception as exc:
            record_results.append(
                {
                    "path": str(path.relative_to(root)),
                    "errors": [f"could not parse JSON: {exc}"],
                }
            )
            continue
        for record in _records_from_document(document):
            records_checked += 1
            record_results.append(
                {
                    "path": str(path.relative_to(root)),
                    "record_id": record.get("id"),
                    "errors": validate_evidence_record(record, root),
                }
            )
        if isinstance(document, dict) and "tool_output_type" in document:
            errors = validate_against_schema(document, "tool-output.schema.json", root)
            if errors:
                record_results.append(
                    {"path": str(path.relative_to(root)), "errors": errors}
                )

    failures = [r for r in record_results if r.get("errors")]
    return {
        "tool_output_type": "validation_report",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        # We use the same static timestamp as aegisgraph.constants so the
        # diff between mutating and non-mutating reports is exactly zero.
        "generated_at": "2026-05-05T00:00:00Z",
        "safety_posture": "private_by_default",
        "schemas_checked": len(list((root / "schema").glob("*.schema.json"))),
        "records_checked": records_checked,
        "schema_errors": schema_errors,
        "record_results": record_results,
        "status": "pass" if not schema_errors and not failures else "fail",
    }


def run(non_mutating: bool, root: Path | None = None) -> dict[str, Any]:
    """Public entry: dispatch to mutating or non-mutating implementation.

    Mutating mode delegates to aegisgraph.validation.validate_repo (which
    writes validation-report.json). Non-mutating mode uses our
    re-implementation that returns the report only.
    """
    target_root = root if root is not None else ROOT
    if _non_mutating_requested(non_mutating):
        return validate_repo_non_mutating(target_root)
    from aegisgraph.validation import validate_repo

    return validate_repo(target_root)


def _print_report(report: dict[str, Any], non_mutating: bool) -> None:
    mode = "non-mutating" if non_mutating else "mutating"
    print(
        f"validation {report['status']} ({mode}): "
        f"{report['records_checked']} evidence records checked"
    )
    if report.get("schema_errors"):
        print("schema errors:")
        for err in report["schema_errors"]:
            print(f"  - {err}")
    for result in report.get("record_results", []):
        if result.get("errors"):
            print(f"{result.get('record_id', result['path'])}:")
            for err in result["errors"]:
                print(f"  - {err}")


def main(argv: list[str] | None = None) -> int:
    """Stand-alone entry: `python -m validator.validate_evidence [--non-mutating]`.

    Backwards compatible with the legacy `python validator/validate_evidence.py`
    invocation that just delegated to `aegisgraph validate`.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    non_mutating = False
    if "--non-mutating" in args:
        args.remove("--non-mutating")
        non_mutating = True
    if args:
        print(
            f"unknown args: {args!r}; usage: python -m validator.validate_evidence [--non-mutating]",
            file=sys.stderr,
        )
        return 2
    report = run(non_mutating=non_mutating)
    _print_report(report, non_mutating=non_mutating or _non_mutating_requested(False))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
