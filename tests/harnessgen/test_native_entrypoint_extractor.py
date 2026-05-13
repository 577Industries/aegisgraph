"""Native entrypoint extractor: parses a C/C++ header signature and returns
a structured representation usable by the libfuzzer template.

The extractor is heuristic (regex-based) at M3.1 — full Clang AST integration
is deferred. The contract that must hold at M3.1:

  * Given a header excerpt containing a function declaration, the extractor
    returns an `EntryPoint` dataclass with:
      - name: function identifier
      - return_type: e.g. "uint8_t*"
      - params: list of (type, name) tuples
      - header: the include path (e.g. "webp/decode.h")
  * Unknown signatures raise `EntryPointNotFoundError`.
  * Multiple candidates in a single header find the named one only.

This test exercises only the extractor surface; no Clang invocation, no
filesystem reads (input is a string).
"""

from __future__ import annotations

import pytest

from aegisgraph.harnessgen.extractors.native_entrypoint import (
    EntryPoint,
    EntryPointNotFoundError,
    extract_from_header_text,
)


WEBP_HEADER = """
// excerpt of webp/decode.h
#ifndef WEBP_WEBP_DECODE_H_
#define WEBP_WEBP_DECODE_H_

#include <stddef.h>

// Decodes WEBP images pointed to by data and returns RGB samples.
WEBP_EXTERN uint8_t* WebPDecodeRGB(const uint8_t* data, size_t data_size,
                                   int* width, int* height);

WEBP_EXTERN void WebPFree(void* ptr);

#endif
"""


def test_extract_webp_decode_rgb_returns_entrypoint() -> None:
    entry = extract_from_header_text(
        header_text=WEBP_HEADER,
        function_name="WebPDecodeRGB",
        header_path="webp/decode.h",
    )
    assert isinstance(entry, EntryPoint)
    assert entry.name == "WebPDecodeRGB"
    assert entry.header == "webp/decode.h"


def test_extract_returns_data_size_param_pair() -> None:
    entry = extract_from_header_text(
        header_text=WEBP_HEADER,
        function_name="WebPDecodeRGB",
        header_path="webp/decode.h",
    )
    param_names = [p.name for p in entry.params]
    # The libfuzzer harness will rebind 'data' and 'data_size' to its
    # (data, size) inputs, so we need both parsed.
    assert "data" in param_names
    assert "data_size" in param_names


def test_extract_return_type_is_uint8_pointer() -> None:
    entry = extract_from_header_text(
        header_text=WEBP_HEADER,
        function_name="WebPDecodeRGB",
        header_path="webp/decode.h",
    )
    # The exact spacing isn't part of the contract; the asterisk presence is.
    assert "uint8_t" in entry.return_type
    assert "*" in entry.return_type


def test_extract_unknown_function_raises() -> None:
    with pytest.raises(EntryPointNotFoundError):
        extract_from_header_text(
            header_text=WEBP_HEADER,
            function_name="DefinitelyNotInThisHeader",
            header_path="webp/decode.h",
        )


def test_extract_picks_named_function_not_first_match() -> None:
    """If a header has multiple decls, the extractor returns the one we
    asked for, not the first one in source order."""
    entry = extract_from_header_text(
        header_text=WEBP_HEADER,
        function_name="WebPFree",
        header_path="webp/decode.h",
    )
    assert entry.name == "WebPFree"
    assert entry.return_type.strip() == "void"
