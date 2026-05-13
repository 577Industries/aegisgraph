"""Parse a C/C++ header text to extract a named function signature.

This is the M3.1 regex extractor. It is heuristic — Clang AST integration
is deferred to a later milestone. The contract is intentionally narrow:

  given the text of a header file and a function name, return an
  EntryPoint(name, return_type, params, header).

The extractor handles the libwebp shape:

    WEBP_EXTERN uint8_t* WebPDecodeRGB(const uint8_t* data, size_t data_size,
                                       int* width, int* height);

and the simpler shapes used by other native targets:

    void WebPFree(void* ptr);
    int foo(int a, int b);

It deliberately does NOT handle:
  * variadic functions (...) — none of our M3.1 targets need them
  * function pointers as return types — out of scope at v0
  * nested template instantiations — C++ classes are a future milestone

Anything unparseable raises EntryPointNotFoundError; the caller is
expected to retry with a hand-written EntryPoint or to extend the
extractor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


class EntryPointNotFoundError(LookupError):
    """Raised when the named function is not found in the header text.

    Fail-closed: the caller must NOT proceed with a guessed signature.
    The harness template depends on the parsed type to render the call
    correctly; a wrong return type or missing param produces invalid C++.
    """


@dataclass(frozen=True)
class Param:
    """One parameter of a parsed function signature.

    `type` is the C/C++ type as it appears in the header (including
    pointer/qualifier annotation). `name` is the formal parameter name.
    Both are kept as written so the template can faithfully render
    `const uint8_t* data` (not `uint8_t *data`, which would change the
    extern "C" mangling on some compilers).
    """

    type: str
    name: str


@dataclass(frozen=True)
class EntryPoint:
    """A parsed C/C++ function signature ready for template rendering."""

    name: str
    return_type: str
    params: list[Param] = field(default_factory=list)
    header: str = ""


# Heuristic regex: matches `[qualifiers] return_type name(arg_list);`
# - qualifiers are dropped (WEBP_EXTERN, extern, static, inline)
# - return_type may include pointers / const
# - arg_list is captured verbatim and split below
_DECL_RE = re.compile(
    r"""
    (?:WEBP_EXTERN|extern|static|inline|\s)*    # ignorable qualifiers
    \s*
    (?P<rtype>[\w:\s*&<>,]+?)                    # return type (lazy)
    \s+
    (?P<fname>\w+)                                # function name
    \s*
    \(
    (?P<args>[^)]*)                               # argument list
    \)
    \s*;
    """,
    re.VERBOSE,
)


def _strip_qualifiers(raw: str) -> str:
    """Drop leading project-specific macros from a return type.

    Some headers wrap declarations with macros like WEBP_EXTERN that
    expand to `extern` or visibility attributes. The regex above strips
    the common ones, but if a raw return type still has stray leading
    macros, drop them here.
    """
    rtype = raw.strip()
    # Strip any macro-looking ALL_CAPS prefix that survived the regex.
    rtype = re.sub(r"^(?:[A-Z][A-Z0-9_]+\s+)+", "", rtype)
    return rtype.strip()


def _split_args(arg_list: str) -> list[Param]:
    """Split an arg list into `Param(type, name)` entries.

    Naive comma split — fine for the M3.1 targets, which don't use
    template arguments, function pointers, or default values.
    """
    args: list[Param] = []
    raw = arg_list.strip()
    if not raw or raw == "void":
        return args
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        # The parameter name is the trailing identifier (possibly attached
        # to a pointer/asterisk). Split off the last word; the rest is the
        # type. `const uint8_t* data` -> type=`const uint8_t*`, name=`data`.
        m = re.match(r"^(.*?)([*\s])(\w+)\s*$", token)
        if not m:
            # Anonymous param (e.g. `int`) — give it an empty name. The
            # template won't use it for the (data, size) rebinding anyway.
            args.append(Param(type=token, name=""))
            continue
        type_part = (m.group(1) + m.group(2)).strip()
        name_part = m.group(3)
        args.append(Param(type=type_part, name=name_part))
    return args


def _preprocess(header_text: str) -> str:
    """Strip noise that confuses the declaration regex.

    Drops:
      * preprocessor lines (#include, #define, #ifdef, #endif, #ifndef, ...)
      * single-line // comments
      * /* ... */ block comments (single-line, non-greedy)
      * trailing whitespace on lines

    Leaves the declarations themselves untouched.
    """
    # /* ... */ block comments — non-greedy across lines.
    text = re.sub(r"/\*.*?\*/", "", header_text, flags=re.DOTALL)
    out_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("//"):
            continue
        # Trim inline `// comment` tails.
        if "//" in line:
            line = line.split("//", 1)[0]
        out_lines.append(line.rstrip())
    return "\n".join(out_lines)


def extract_from_header_text(
    header_text: str,
    function_name: str,
    header_path: str = "",
) -> EntryPoint:
    """Find `function_name` in `header_text` and return its EntryPoint.

    Raises EntryPointNotFoundError if the function is absent.
    """
    cleaned = _preprocess(header_text)
    for match in _DECL_RE.finditer(cleaned):
        if match.group("fname") != function_name:
            continue
        rtype = _strip_qualifiers(match.group("rtype"))
        params = _split_args(match.group("args"))
        return EntryPoint(
            name=function_name,
            return_type=rtype,
            params=params,
            header=header_path,
        )
    raise EntryPointNotFoundError(
        f"function {function_name!r} not found in header text "
        f"(searched {len(header_text)} chars)"
    )


__all__ = [
    "EntryPoint",
    "EntryPointNotFoundError",
    "Param",
    "extract_from_header_text",
]
