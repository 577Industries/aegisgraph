"""Jinja2 templates for HarnessGen + render helpers.

Four templates ship after M5.1:
  libfuzzer_native.cc.j2  : LLVMFuzzerTestOneInput wrapping a native entry
                            function (Asemarefactor.md lines 215-225 shape)
  build/native.Makefile.j2 : ASAN + UBSan + libfuzzer build recipe (native)
  jazzer_jvm.java.j2       : fuzzerTestOneInput wrapping a JVM target method
                             (Asemarefactor.md lines 168-186 shape)
  build/jvm.gradle.j2      : Gradle build stub for the JVM harness (Jazzer
                             + parser module only; no full host app)

`render_libfuzzer_native(context)`, `render_native_makefile(context)`,
`render_jazzer_jvm(context)`, and `render_jvm_gradle(context)` return the
rendered text. The templates are plain-text C++/Java/Makefile/Gradle —
NOT HTML, so autoescape is off (same rationale as
aegisgraph/disclosure/templates).

Each render output is screened for "raw bytes leakage" tokens by the
caller; templates themselves are parameterized over names/paths/flags
only, never over bytes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import jinja2


TEMPLATES_DIR = Path(__file__).resolve().parent
BUILD_DIR = TEMPLATES_DIR / "build"

LIBFUZZER_TEMPLATE_NAME = "libfuzzer_native.cc.j2"
NATIVE_MAKEFILE_TEMPLATE_NAME = "build/native.Makefile.j2"
JAZZER_JVM_TEMPLATE_NAME = "jazzer_jvm.java.j2"
JVM_GRADLE_TEMPLATE_NAME = "build/jvm.gradle.j2"


def _env() -> jinja2.Environment:
    """Build a Jinja2 environment scoped to the templates directory.

    autoescape is OFF intentionally: these render plain-text source code
    (C++ and Makefile), not HTML. Same call-site rationale as
    aegisgraph.disclosure.templates._env — the templates are inspected by
    test suites that check for raw-bytes leakage tokens and forbidden
    keywords.
    """
    # nosemgrep: direct-use-of-jinja2  # plain-text C++/Makefile, not HTML
    return jinja2.Environment(  # noqa: S701
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def render_libfuzzer_native(context: dict[str, Any]) -> str:
    """Render the libFuzzer native-target harness for `context`.

    Required context keys:
      harness_id          : str — also written into the generator comment
      header              : str — include path, e.g. "webp/decode.h"
      entry_function      : str — function name to call (e.g. WebPDecodeRGB)
      free_function       : str — paired free (e.g. WebPFree), or "" to omit
      entry_return_type   : str — return type of the entry function
      entry_data_param    : str — name of the data-pointer param
      entry_size_param    : str — name of the size param
      out_dims            : list[str] — names of the int* output params
                            (e.g. ["w", "h"] for WebPDecodeRGB)
    """
    env = _env()
    template = env.get_template(LIBFUZZER_TEMPLATE_NAME)
    # nosemgrep: direct-use-of-jinja2  # plain-text render; not user-supplied HTML
    return template.render(**context)


def render_native_makefile(context: dict[str, Any]) -> str:
    """Render the native fuzz harness Makefile for `context`.

    Required context keys:
      harness_id          : str
      harness_source      : str — filename of the .cc source
      harness_binary      : str — output binary name
      header_include_dirs : list[str] — -I paths
      link_libs           : list[str] — -l libs (e.g. ["webp"])
      compiler            : str — "clang++" recommended
    """
    env = _env()
    template = env.get_template(NATIVE_MAKEFILE_TEMPLATE_NAME)
    # nosemgrep: direct-use-of-jinja2  # plain-text render; not user-supplied HTML
    return template.render(**context)


def render_jazzer_jvm(context: dict[str, Any]) -> str:
    """Render the Jazzer JVM harness for `context`.

    Required context keys:
      harness_id          : str — also written into the generator comment
      package             : str — Java package, e.g. "org.aegisgraph.fuzz"
      target_import       : str — FQN of the target class to import
      fuzzer_class_name   : str — name of the generated public class
      target_call         : str — the call expression invoked inside the
                            try-block, e.g. "LinkPreviewUtil.findValidPreviewUrls(input)"
      expected_exceptions : list[str] — Java exception types swallowed in
                            the catch clause (multi-catch via `|`)
    """
    env = _env()
    template = env.get_template(JAZZER_JVM_TEMPLATE_NAME)
    # nosemgrep: direct-use-of-jinja2  # plain-text render; not user-supplied HTML
    return template.render(**context)


def render_jvm_gradle(context: dict[str, Any]) -> str:
    """Render the JVM fuzz harness Gradle build for `context`.

    Required context keys:
      harness_id            : str
      target_module         : str — Gradle coordinate of the parser module,
                              e.g. "org.thoughtcrime.securesms:link-preview-parser"
      target_module_version : str — PLACEHOLDER at M5.1; pinned at M5.1.b
      jazzer_version        : str — Jazzer release (placeholder ok at M5.1)
      java_version          : str — JDK version number (e.g. "17")
      fuzzer_main_class     : str — FQN of the fuzzer entrypoint class
      harness_source        : str — filename of the .java source
    """
    env = _env()
    template = env.get_template(JVM_GRADLE_TEMPLATE_NAME)
    # nosemgrep: direct-use-of-jinja2  # plain-text render; not user-supplied HTML
    return template.render(**context)


__all__ = [
    "render_jazzer_jvm",
    "render_jvm_gradle",
    "render_libfuzzer_native",
    "render_native_makefile",
    "TEMPLATES_DIR",
]
