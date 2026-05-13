"""Jinja2 templates for HarnessGen + render helpers.

Two templates ship at M3.1:
  libfuzzer_native.cc.j2  : LLVMFuzzerTestOneInput wrapping a native entry
                            function (Asemarefactor.md lines 215-225 shape)
  build/native.Makefile.j2 : ASAN + UBSan + libfuzzer build recipe

`render_libfuzzer_native(context)` and `render_native_makefile(context)`
return the rendered text. The templates are plain-text C++/Makefile — NOT
HTML, so autoescape is off (same rationale as
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


__all__ = [
    "render_libfuzzer_native",
    "render_native_makefile",
    "TEMPLATES_DIR",
]
