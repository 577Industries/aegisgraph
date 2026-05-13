# HarnessGen (Engine 2)

HarnessGen reads attack-surface paths from the AegisGraph extraction
graph and emits fuzz harnesses at graph-identified entry points across
JVM, native, and Rust. Each generated harness carries an ASAN + UBSan +
libfuzzer build recipe, is wired to run in a sandboxed docker container
on a self-hosted runner, and emits `AG-CRASH-*` evidence records that
validate against `schema/crash.schema.json`.

## Module layout (M3.1)

```
aegisgraph/harnessgen/
  __init__.py
  harnessgen.py                 # orchestrator + crash-record builder + CLI
  extractors/
    native_entrypoint.py        # regex-based C/C++ header signature parser
  templates/
    libfuzzer_native.cc.j2      # LLVMFuzzerTestOneInput wrapper template
    build/native.Makefile.j2    # ASAN + UBSan + libfuzzer Makefile
  runners/
    docker_runner.py            # subprocess wrapper (mock-friendly)
    coverage_collector.py       # libFuzzer stdout -> summary record
  corpus/
    seed_from_smabench.py       # SMABench -> dedup'd seed corpus
    dictionaries/               # format-aware libFuzzer dict files (later)
```

The first concrete artifact ships under `reprochain/harness/libwebp/`:

```
WebPDecodeRGB.harness.cc        rendered from libfuzzer_native.cc.j2
Makefile                         rendered from native.Makefile.j2
manifest.json                    hash-only metadata
```

## CLI

```
$ python3 -m aegisgraph.harnessgen.harnessgen --help
$ python3 -m aegisgraph.harnessgen.harnessgen generate-harness libwebp
```

The `run` subcommand is a stub at M3.1; live fuzz invocation happens on
the self-hosted runner via `make harnessgen-native PATH_ID=<path>` (the
make target ships in a later milestone).

## Devcontainer tooling

Live fuzz runs need:
  * Clang 18 with `libfuzzer` support (`-fsanitize=fuzzer`)
  * `libwebp-dev` headers for the libwebp target
  * Docker for sandboxed execution

The Python scaffold runs without any of these — all subprocess calls in
the test suite are mocked. The devcontainer must install them for the
self-hosted runner; the harness `Makefile` documents the required flags.

## No-bytes contract

Every AG-CRASH-* record emitted by `build_crash_record` is hash-only:

  * `crash_sha256` is the SHA-256 of the bytes; the bytes are NEVER
    serialized into the record.
  * `stack_trace_hash` is the SHA-256 of a canonicalized trace; the trace
    text is NEVER serialized.
  * `crash_class` is the top-level sanitizer/exception category only — no
    line numbers, no source paths.

The raw bytes (if retained at all) live under
`reprochain/corpora-private/<crash_sha256>` and are referenced by hash
from the schema-validated record. See ADR-0013 for the full rationale.

## Tests

```
tests/harnessgen/
  test_native_entrypoint_extractor.py
  test_libfuzzer_template_renders.py
  test_native_makefile_template_renders.py
  test_docker_runner_subprocess_contract.py     (subprocess MOCKED)
  test_coverage_collector_parses_libfuzzer_stdout.py
  test_crash_record_emission_validates_schema.py
  test_crash_record_no_raw_bytes_regression.py
  test_corpus_seeding_dedups.py
  test_libwebp_harness_artifact_present.py
  test_harnessgen_module_imports.py
```

No live `docker`, no live fuzz, no live target probing in CI.
