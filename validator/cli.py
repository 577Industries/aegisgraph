"""validator CLI dispatcher.

Subcommands:

  validate         [--non-mutating]
      Run the schema + safety + hash-chain validator. By default this
      delegates to `aegisgraph validate` (which writes
      validation-report.json). With --non-mutating, it returns the same
      report without writing to disk — used by CI / external reviewers
      who must not alter tracked files.

  strict-tooling   --required <comma-separated-tool-names>
      Probe the listed tools (e.g. clang,codeql,semgrep,docker,java,go,rustc).
      Exit 1 if any required tool is missing or below pin. Delegates to
      aegisgraph.tooling so this stream does not duplicate the pin table.
      The caller passes a custom subset; the integration stream's
      REQUIRED_TOOLS table remains authoritative for `make reproduce`.

  sanitize-check   <export-tree-path>
      Scan a public-sanitized export tree for forbidden patterns,
      misclassified safety-posture, embedded crash bytes, and overclaim
      promotion. Used by aegisgraph/export.py via lazy import and by
      .github/workflows/sanitize.yml as the fail-closed gate.

  traceability
      Emit reports/traceability_matrix.{json,md} from SPEC.md headers,
      docs/proposal-claims-index.yml, docs/dsip-requirements.yml, and
      on-disk evidence files.

The CLI is the integration surface that `make sanitize-check`,
`make traceability`, and CI workflows call.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

# Repo root (one level up from validator/). Some subcommands accept a
# --root override for tests; the default targets the worktree's repo
# root.
_ROOT = Path(__file__).resolve().parents[1]


def _strict_tooling_required(req: str) -> list[str]:
    """Parse the --required argument: comma-separated tool names."""
    return [name.strip() for name in (req or "").split(",") if name.strip()]


def cmd_validate(args: argparse.Namespace) -> int:
    """`validator.cli validate [--non-mutating]`."""
    # Local import: `validator.validate_evidence` does the heavy work and
    # decides between mutating / non-mutating dispatch.
    from validator import validate_evidence

    return validate_evidence.main(
        ["--non-mutating"] if args.non_mutating else []
    )


def cmd_strict_tooling(args: argparse.Namespace) -> int:
    """`validator.cli strict-tooling --required clang,codeql,...`.

    Delegates to aegisgraph.tooling. We do NOT duplicate the
    REQUIRED_TOOLS table; we just probe the requested subset and
    fail-closed on any miss.
    """
    required = _strict_tooling_required(args.required)
    if not required:
        print(
            "error: --required must list at least one tool "
            "(e.g. --required clang,codeql,semgrep)",
            file=sys.stderr,
        )
        return 2

    from aegisgraph.tooling import (
        REQUIRED_TOOLS,
        TOOL_COMMANDS,
        _meets_min,
        _version_for,
    )

    # Build a name → RequiredTool mapping so we can preserve the
    # canonical min_version + check_command rather than re-listing them.
    by_name = {t.name: t for t in REQUIRED_TOOLS}
    missing: list[str] = []
    below: list[tuple[str, str, str]] = []  # (name, observed, min)
    not_in_table: list[str] = []

    for name in required:
        canonical = by_name.get(name)
        if canonical is None:
            not_in_table.append(name)
            continue
        # Probe via the canonical check_command so we honor whatever
        # special-case command (e.g. codeql version --format=json) the
        # integration stream pinned.
        info = _version_for(canonical.check_command)
        if not info.get("available"):
            missing.append(name)
            continue
        if not _meets_min(info.get("version"), canonical.min_version):
            below.append((name, info.get("version") or "", canonical.min_version))

    ok = not missing and not below and not not_in_table
    if ok:
        print(
            f"strict tooling gate: PASS (verified {len(required)} required tool(s))"
        )
        return 0

    print("strict tooling gate: FAIL")
    for name in not_in_table:
        print(
            f"  UNKNOWN: {name!r} is not in REQUIRED_TOOLS; "
            f"valid names: {sorted(by_name)}"
        )
    for name in missing:
        print(f"  MISSING: {name}")
    for name, observed, required_min in below:
        print(
            f"  BELOW MIN: {name} observed={observed!r} required>={required_min}"
        )
    print(
        "hint: rebuild the devcontainer (devcontainer/Dockerfile pins versions) "
        "or pass a smaller --required subset."
    )
    return 1


def cmd_sanitize_check(args: argparse.Namespace) -> int:
    """`validator.cli sanitize-check <path>`."""
    from validator.sanitize_check import render_failures, scan_export_tree

    target = Path(args.path)
    report = scan_export_tree(target)
    for line in render_failures(report):
        print(line)
    return 0 if report.ok else 1


def cmd_traceability(_args: argparse.Namespace) -> int:
    """`validator.cli traceability`."""
    from validator.traceability_matrix import main as traceability_main

    return traceability_main([])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="validator",
        description=(
            "AegisGraph Tier 3 evidence validator — non-mutating, "
            "sanitize-check, traceability, and strict-tooling."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser(
        "validate",
        help="run schema + safety + hash-chain validator",
    )
    p_validate.add_argument(
        "--non-mutating",
        action="store_true",
        help=(
            "do not write validation-report.json. Equivalent to setting "
            "AEGISGRAPH_VALIDATOR_NON_MUTATING=1. Use this in third-party "
            "verification flows."
        ),
    )
    p_validate.set_defaults(func=cmd_validate)

    p_strict = sub.add_parser(
        "strict-tooling",
        help="fail-closed probe of a required-tool subset",
    )
    p_strict.add_argument(
        "--required",
        type=str,
        default="",
        help=(
            "comma-separated tool names from REQUIRED_TOOLS to enforce; "
            "e.g. --required clang,codeql,semgrep,docker,java,go,rustc"
        ),
    )
    p_strict.set_defaults(func=cmd_strict_tooling)

    p_sanitize = sub.add_parser(
        "sanitize-check",
        help="scan a public-sanitized export tree for forbidden patterns",
    )
    p_sanitize.add_argument(
        "path",
        type=str,
        help="path to the export tree (e.g. exports/public-sanitized)",
    )
    p_sanitize.set_defaults(func=cmd_sanitize_check)

    p_trace = sub.add_parser(
        "traceability",
        help="emit reports/traceability_matrix.{json,md}",
    )
    p_trace.set_defaults(func=cmd_traceability)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
