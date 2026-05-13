"""Smoke test: every workbench module imports cleanly."""

from __future__ import annotations


def test_workbench_package_imports() -> None:
    import aegisgraph.workbench as wb

    assert hasattr(wb, "__all__")
    assert "registry" in wb.__all__


def test_workbench_submodules_import() -> None:
    from aegisgraph.workbench import (  # noqa: F401
        cli,
        filters,
        finding_detail,
        finding_list,
        packet_export,
        registry,
    )


def test_workbench_subparser_is_mounted_on_main_cli() -> None:
    from aegisgraph.cli import build_parser

    parser = build_parser()
    # argparse hides the subparsers behind _SubParsersAction; we can
    # introspect parse_args() error by attempting to parse `workbench list`.
    args = parser.parse_args(["workbench", "list", "--format", "json"])
    assert args.command == "workbench"
    assert args.workbench_command == "list"
    assert args.format == "json"


def test_workbench_subparser_packet_args() -> None:
    from aegisgraph.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(
        ["workbench", "packet", "--top", "5", "--out", "exports/test"]
    )
    assert args.workbench_command == "packet"
    assert args.top == 5
    assert args.out == "exports/test"
