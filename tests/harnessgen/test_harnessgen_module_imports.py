"""Smoke test: aegisgraph.harnessgen and submodules import cleanly + CLI smoke.

This is the M3.1 sanity check that Engine 2 (HarnessGen) v0 scaffold exists
and is importable. Behavior is exercised in sibling test modules; here we
only confirm:

  * `aegisgraph.harnessgen` is importable.
  * Submodules (extractors, templates, runners, corpus) import.
  * `harnessgen --help` returns 0 via the CLI entry.
  * `generate-harness libwebp` runs end-to-end and writes the expected
    files. (Real `run` subcommand is deferred per task spec.)
"""

from __future__ import annotations

import importlib


def test_harnessgen_package_imports() -> None:
    mod = importlib.import_module("aegisgraph.harnessgen")
    assert mod is not None


def test_extractor_module_imports() -> None:
    mod = importlib.import_module("aegisgraph.harnessgen.extractors.native_entrypoint")
    assert hasattr(mod, "extract_from_header_text")


def test_templates_module_imports() -> None:
    mod = importlib.import_module("aegisgraph.harnessgen.templates")
    assert hasattr(mod, "render_libfuzzer_native")
    assert hasattr(mod, "render_native_makefile")


def test_runners_module_imports() -> None:
    docker_mod = importlib.import_module("aegisgraph.harnessgen.runners.docker_runner")
    cov_mod = importlib.import_module("aegisgraph.harnessgen.runners.coverage_collector")
    assert hasattr(docker_mod, "DockerRunner")
    assert hasattr(cov_mod, "parse_libfuzzer_stdout")


def test_corpus_module_imports() -> None:
    mod = importlib.import_module("aegisgraph.harnessgen.corpus.seed_from_smabench")
    assert hasattr(mod, "seed_corpus")


def test_cli_help_returns_zero() -> None:
    """`harnessgen --help` must exit 0. This is the M3.1 wired-stub
    requirement — full `run` subcommand is deferred."""
    from aegisgraph.harnessgen.harnessgen import build_parser

    parser = build_parser()
    # argparse exits via SystemExit(0) on --help.
    try:
        parser.parse_args(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
        return
    raise AssertionError("--help did not call SystemExit")


def test_cli_generate_harness_libwebp_smoke(tmp_path) -> None:
    """`generate-harness libwebp --output-dir <tmp>` produces the harness
    artifacts. Uses tmp_path so the test doesn't mutate the committed
    reprochain/harness/libwebp directory."""
    from aegisgraph.harnessgen.harnessgen import generate_harness_for_path

    result = generate_harness_for_path("libwebp", output_dir=tmp_path)
    assert (tmp_path / "WebPDecodeRGB.harness.cc").is_file()
    assert (tmp_path / "Makefile").is_file()
    assert (tmp_path / "manifest.json").is_file()
    assert result["harness_id"] == "WebPDecodeRGB"
