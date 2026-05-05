from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import extraction, export, polydiff, reprochain, smabench, tooling
from .io import repo_root
from .validation import validate_repo


def _root() -> Path:
    return repo_root()


def cmd_tooling(_args: argparse.Namespace) -> int:
    report = tooling.write_tooling_report(_root())
    available = sum(1 for tool in report["tools"].values() if tool.get("available"))
    print(f"tooling report written: {available}/{len(report['tools'])} tools available")
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
        print(f"polydiff regression {report['tier_p1_status']}: {len(report['records'])} evidence records")
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
        manifest = export.export_public_sanitized(_root())
        print(f"public sanitized candidate: {len(manifest['artifacts'])} artifacts, release_authorized={manifest['release_authorized']}")
    else:  # pragma: no cover
        raise AssertionError(args.export_command)
    return 0


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

    smabench_parser = subparsers.add_parser("smabench")
    smabench_subparsers = smabench_parser.add_subparsers(dest="smabench_command", required=True)
    smabench_run = smabench_subparsers.add_parser("run")
    smabench_run.set_defaults(func=cmd_smabench)

    export_parser = subparsers.add_parser("export")
    export_subparsers = export_parser.add_subparsers(dest="export_command", required=True)
    export_private = export_subparsers.add_parser("private")
    export_private.set_defaults(func=cmd_export)
    export_public = export_subparsers.add_parser("public-sanitized")
    export_public.set_defaults(func=cmd_export)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
