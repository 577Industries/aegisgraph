"""AegisGraph Engine 2: HarnessGen.

HarnessGen reads attack-surface paths from the AegisGraph extraction graph
and emits fuzz harnesses at graph-identified entry points across JVM,
native, and Rust. Each generated harness:

  * is auto-generated from a Jinja2 template + an EntryPoint extracted
    from the target's headers (native) or source AST (JVM / Rust);
  * carries an ASAN + UBSan + libfuzzer build recipe;
  * is wired to be run in a sandboxed docker container on a self-hosted
    runner — not in CI, not on developer workstations;
  * emits AG-CRASH-* records that validate against
    `schema/crash.schema.json` and never carry raw bytes.

At M3.1 the scaffold ships:
  * extractors.native_entrypoint  : regex-based C/C++ header signature parser
  * templates                     : libfuzzer_native.cc.j2 + native.Makefile.j2
  * runners.docker_runner         : subprocess wrapper (mock-friendly)
  * runners.coverage_collector    : libFuzzer stdout -> summary record
  * corpus.seed_from_smabench     : SMABench corpus -> dedup'd fuzz seeds
  * harnessgen.py                 : CLI entry + crash-record builder

The first concrete artifact is `reprochain/harness/libwebp/`, the
libwebp `WebPDecodeRGB` harness from Asemarefactor.md lines 215-225.

Devcontainer note: live fuzz runs need Clang 18 + libfuzzer support +
libwebp dev headers. The Python scaffold runs without any of those
(subprocess is mocked in tests).
"""

from __future__ import annotations
