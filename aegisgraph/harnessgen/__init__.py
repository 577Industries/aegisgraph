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
  * templates.libfuzzer_native    : LLVMFuzzerTestOneInput wrapper template
  * templates.native_makefile     : ASAN+UBSan+libfuzzer build recipe
  * runners.docker_runner         : subprocess wrapper (mock-friendly)
  * runners.coverage_collector    : libFuzzer stdout -> summary record
  * corpus.seed_from_smabench     : SMABench corpus -> dedup'd fuzz seeds
  * harnessgen.py                 : CLI entry + crash-record builder
  * reprochain/harness/libwebp/   : first concrete artifact (native;
                                    WebPDecodeRGB per Asemarefactor.md
                                    lines 215-225)

At M5.1 the JVM substream lands:
  * extractors.jvm_entrypoint     : regex+comment-aware Java/Kotlin
                                    method signature parser
  * templates.jazzer_jvm          : fuzzerTestOneInput Jazzer wrapper
                                    template (Asemarefactor.md 168-186)
  * templates.jvm_gradle          : Gradle build stub (parser module
                                    + Jazzer only; no full host app)
  * reprochain/harness/signal_linkpreview/  : second concrete artifact
                                    (JVM; LinkPreviewUtil.findValidPreviewUrls)

Engine 2 entry-point coverage at M5.1: 2/5 (libwebp native + Signal
LinkPreviewUtil JVM). M6 adds the remaining three (Rust + two more JVM
parsers per the M5-M7 plan).

Devcontainer note: live fuzz runs need Clang 18 + libfuzzer support +
libwebp dev headers (native) and JDK 17 + Gradle + Jazzer driver (JVM).
The Python scaffold runs without any of those (subprocess is mocked in
tests; Jazzer/Gradle never invoked from pytest).
"""

from __future__ import annotations
