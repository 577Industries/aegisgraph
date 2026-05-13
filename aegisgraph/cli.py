from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from . import extraction, export, polydiff, reprochain, smabench, tooling
from .disclosure import ledger as disclosure_ledger
from .disclosure.pipeline import embargo_timer
from .io import repo_root
from .validation import validate_repo


def _root() -> Path:
    return repo_root()


def _strict_requested(args: argparse.Namespace) -> bool:
    if getattr(args, "strict", False):
        return True
    return os.environ.get("AEGISGRAPH_STRICT_TOOLING") == "1"


def cmd_tooling(args: argparse.Namespace) -> int:
    report = tooling.write_tooling_report(_root())
    available = sum(1 for tool in report["tools"].values() if tool.get("available"))
    print(f"tooling report written: {available}/{len(report['tools'])} tools available")

    if _strict_requested(args):
        strict = report.get("strict_evaluation", {})
        if strict.get("ok"):
            print("strict tooling gate: PASS")
            return 0
        print("strict tooling gate: FAIL")
        for line in tooling.strict_summary_lines(report):
            print(line)
        print(
            "hint: rebuild the devcontainer (devcontainer/Dockerfile pins versions) "
            "or unset AEGISGRAPH_STRICT_TOOLING / drop --strict to ignore."
        )
        return 1
    return 0


def cmd_validate(_args: argparse.Namespace) -> int:
    report = validate_repo(_root())
    print(f"validation {report['status']}: {report['records_checked']} evidence records checked")
    if report["schema_errors"]:
        print("schema errors:")
        for error in report["schema_errors"]:
            print(f"  - {error}")
    for result in report["record_results"]:
        if result.get("errors"):
            print(f"{result.get('record_id', result['path'])}:")
            for error in result["errors"]:
                print(f"  - {error}")
    return 0 if report["status"] == "pass" else 1


def cmd_extract(_args: argparse.Namespace) -> int:
    manifest = extraction.run_extract(_root())
    print(f"extraction scaffold wrote {len(manifest['outputs'])} graph outputs")
    return 0


def cmd_reprochain(args: argparse.Namespace) -> int:
    if args.reprochain_command == "build":
        manifest = reprochain.build(_root())
        print(f"reprochain build status: {manifest['status']}")
    elif args.reprochain_command == "run":
        status = reprochain.run(_root())
        print(f"reprochain run status: {status['status']}")
    elif args.reprochain_command == "map":
        mapping = reprochain.map_targets(_root())
        print(f"reprochain mapped {len(mapping['records'])} target records")
    else:  # pragma: no cover
        raise AssertionError(args.reprochain_command)
    return 0


def cmd_polydiff(args: argparse.Namespace) -> int:
    if args.polydiff_command == "regression":
        report = polydiff.run_regression(_root())
        print(
            f"polydiff regression {report['tier_p1_status']}: "
            f"{len(report['records'])} evidence records, "
            f"{report.get('rediscovered_historical_cves', 0)} historical-CVE rediscoveries"
        )
    elif args.polydiff_command == "fuzz":
        from polydiff.fuzzer.driver import run as fuzz_run
        budget = float(getattr(args, "budget", "60s").rstrip("s"))
        summary = fuzz_run(_root(), budget_seconds=budget)
        print(
            f"polydiff fuzz: {summary['total_inputs']} inputs, "
            f"{summary['interesting']} interesting, "
            f"{len(summary['axes_covered'])} axes covered, "
            f"{len(summary['crashes'])} crashes"
        )
    else:  # pragma: no cover
        raise AssertionError(args.polydiff_command)
    return 0


def cmd_smabench(args: argparse.Namespace) -> int:
    if args.smabench_command == "run":
        results = smabench.run(_root())
        print(f"smabench ring1 corpora: {len(results['rings']['ring1']['corpora'])}")
    else:  # pragma: no cover
        raise AssertionError(args.smabench_command)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    if args.export_command == "private":
        manifest = export.export_private(_root())
        print(f"private export manifest: {len(manifest['artifacts'])} artifacts, validation={manifest['validation_status']}")
    elif args.export_command == "public-sanitized":
        dry_run = bool(getattr(args, "dry_run", False))
        manifest = export.export_public_sanitized(_root(), dry_run=dry_run)
        prefix = "DRY-RUN " if dry_run else ""
        print(
            f"{prefix}public sanitized candidate: {len(manifest['artifacts'])} artifacts, "
            f"release_authorized={manifest['release_authorized']}"
        )
    else:  # pragma: no cover
        raise AssertionError(args.export_command)
    return 0


def _ledger_path_arg(args: argparse.Namespace) -> Path | None:
    raw = getattr(args, "ledger_path", None)
    return Path(raw) if raw else None


def _format_status_line(event_count: int, finding_count: int) -> str:
    return (
        f"disclosure ledger: {event_count} event(s) across "
        f"{finding_count} finding(s)"
    )


def cmd_disclose(args: argparse.Namespace) -> int:
    sub = args.disclose_command
    ledger_override = _ledger_path_arg(args)

    if sub == "ledger":
        # Currently only --verify is wired; future: --tail, --stats.
        if getattr(args, "verify", False):
            errors = disclosure_ledger.verify_chain(ledger_override)
            if not errors:
                target = ledger_override or disclosure_ledger.ledger_path()
                print(f"disclosure ledger chain intact: {target}")
                return 0
            print("disclosure ledger chain has errors:")
            for line in errors:
                print(f"  - {line}")
            return 1
        print("specify --verify (other ledger ops not yet wired)")
        return 2

    if sub == "status":
        events = disclosure_ledger.read_all(ledger_override)
        finding_ids = {
            str(e.get("finding_id", "")) for e in events if e.get("finding_id")
        }
        print(_format_status_line(len(events), len(finding_ids)))
        if events:
            statuses = embargo_timer.compute_status(ledger_override)
            for s in statuses:
                marker = "EXPIRED" if s["expired"] else f"{s['days_remaining']}d"
                print(
                    f"  {s['finding_id']}: {s['current_event_type']} "
                    f"(next: {s['next_action_date']}, {marker})"
                )
        return 0

    if sub == "tick":
        raw_as_of = getattr(args, "as_of", None)
        if raw_as_of:
            as_of = date.fromisoformat(raw_as_of)
        else:
            as_of = datetime.now(tz=timezone.utc).date()
        statuses = embargo_timer.compute_status(
            ledger_path=ledger_override,
            as_of=as_of,
        )
        print(json.dumps(statuses, indent=2, sort_keys=True))
        return 0

    raise AssertionError(f"unknown disclose subcommand: {sub}")  # pragma: no cover


def cmd_reproduce(_args: argparse.Namespace) -> int:
    tooling.write_tooling_report(_root())
    extraction.run_extract(_root())
    reprochain.build(_root())
    reprochain.run(_root())
    reprochain.map_targets(_root())
    polydiff.run_regression(_root())
    smabench.run(_root())
    report = validate_repo(_root())
    export.export_private(_root())
    print(f"reproduce complete: validation={report['status']}")
    return 0 if report["status"] == "pass" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegisgraph", description="AegisGraph Tier 3 research CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    tooling_parser = subparsers.add_parser("tooling")
    tooling_parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "fail with exit 1 if any tool in REQUIRED_TOOLS is missing or below "
            "min_version. Equivalent to setting AEGISGRAPH_STRICT_TOOLING=1."
        ),
    )
    tooling_parser.set_defaults(func=cmd_tooling)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.set_defaults(func=cmd_validate)

    extract_parser = subparsers.add_parser("extract")
    extract_parser.set_defaults(func=cmd_extract)

    reproduce_parser = subparsers.add_parser("reproduce")
    reproduce_parser.set_defaults(func=cmd_reproduce)

    reprochain_parser = subparsers.add_parser("reprochain")
    reprochain_subparsers = reprochain_parser.add_subparsers(dest="reprochain_command", required=True)
    for command in ("build", "run", "map"):
        child = reprochain_subparsers.add_parser(command)
        child.set_defaults(func=cmd_reprochain)

    polydiff_parser = subparsers.add_parser("polydiff")
    polydiff_subparsers = polydiff_parser.add_subparsers(dest="polydiff_command", required=True)
    polydiff_regression = polydiff_subparsers.add_parser("regression")
    polydiff_regression.set_defaults(func=cmd_polydiff)
    polydiff_fuzz = polydiff_subparsers.add_parser("fuzz")
    polydiff_fuzz.add_argument(
        "--budget",
        default="60s",
        help="Wall-clock budget (default: 60s). Local-only; not in `make reproduce`.",
    )
    polydiff_fuzz.set_defaults(func=cmd_polydiff)

    smabench_parser = subparsers.add_parser("smabench")
    smabench_subparsers = smabench_parser.add_subparsers(dest="smabench_command", required=True)
    smabench_run = smabench_subparsers.add_parser("run")
    smabench_run.set_defaults(func=cmd_smabench)

    export_parser = subparsers.add_parser("export")
    export_subparsers = export_parser.add_subparsers(dest="export_command", required=True)
    export_private = export_subparsers.add_parser("private")
    export_private.set_defaults(func=cmd_export)
    export_public = export_subparsers.add_parser("public-sanitized")
    export_public.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "do not write files under exports/public-sanitized/. "
            "Returns the manifest that would be written, including the "
            "release_authorized flag and release_note. Use to verify "
            "outputs without mutating the export tree."
        ),
    )
    export_public.set_defaults(func=cmd_export)

    disclose_parser = subparsers.add_parser(
        "disclose",
        help="coordinated-disclosure ledger + embargo operations",
    )
    disclose_subparsers = disclose_parser.add_subparsers(
        dest="disclose_command", required=True
    )

    disclose_ledger = disclose_subparsers.add_parser(
        "ledger", help="ledger inspection (--verify checks chain integrity)"
    )
    disclose_ledger.add_argument(
        "--verify",
        action="store_true",
        help="verify the hash chain; exit 0 if intact, 1 if errors",
    )
    disclose_ledger.add_argument(
        "--ledger-path",
        default=None,
        help="override ledger file path (default: aegisgraph/disclosure/ledger.jsonl)",
    )
    disclose_ledger.set_defaults(func=cmd_disclose)

    disclose_status = disclose_subparsers.add_parser(
        "status", help="human-readable summary of ledger events"
    )
    disclose_status.add_argument(
        "--ledger-path", default=None, help="override ledger file path"
    )
    disclose_status.set_defaults(func=cmd_disclose)

    disclose_tick = disclose_subparsers.add_parser(
        "tick",
        help=(
            "embargo-timer cron callable; emits per-finding next-action JSON. "
            "Reads the ledger; does NOT write."
        ),
    )
    disclose_tick.add_argument(
        "--ledger-path", default=None, help="override ledger file path"
    )
    disclose_tick.add_argument(
        "--as-of",
        default=None,
        help="evaluation date in YYYY-MM-DD (default: today, UTC)",
    )
    disclose_tick.set_defaults(func=cmd_disclose)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
