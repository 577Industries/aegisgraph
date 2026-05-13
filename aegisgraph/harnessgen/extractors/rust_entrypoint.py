"""Parse a Rust source file to extract a named function signature.

This is the M5.2 regex+comment-aware Rust extractor. It is heuristic — full
syn / rust-analyzer integration is deferred to a later milestone. The
contract is intentionally narrow:

  given the text of a Rust source file and a function name, return a
  RustEntryPoint(function_name, return_type, params, module_path,
  source_path).

The extractor handles the matrix-rust-sdk MessageType::from_slice shape:

    impl MessageType {
        pub fn from_slice(data: &[u8]) -> Result<MessageType, serde_json::Error> {
            ...
        }
    }

and the simpler shapes used by other Rust targets:

    pub fn parse(data: &[u8]) -> Option<Vec<u8>> { ... }
    pub async fn fetch(url: &str) -> Result<String, std::io::Error> { ... }
    pub(crate) fn internal_only(n: i32) -> i32 { n }
    unsafe fn raw_pointer_op(ptr: *const u8) -> u8 { *ptr }

It deliberately does NOT handle:
  * lifetime-bound `<'a>` generic parameters on the fn (function-level
    generics in declaration position) — caller can fall back to a
    hand-written RustEntryPoint
  * where-clauses on the fn declaration (parsed as part of the return type
    sloppily; full where-clause support deferred)
  * proc-macro-generated functions (#[derive] expansions); the extractor
    only sees source as written
  * trait-method declarations without a body (`fn foo();`) — supported
    structurally but rare for fuzz targets

Anything unparseable raises RustEntryPointNotFoundError; the caller is
expected to retry with a hand-written RustEntryPoint or to extend the
extractor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


class RustEntryPointNotFoundError(LookupError):
    """Raised when the named function is not found in the source text.

    Fail-closed: the caller must NOT proceed with a guessed signature.
    The cargo-fuzz template depends on the parsed types to render the
    call correctly; a wrong return type or missing param produces invalid
    Rust.
    """


@dataclass(frozen=True)
class RustParam:
    """One parameter of a parsed Rust function signature.

    `type` is the Rust type spelling as it appears in source (including
    `&`, `&mut`, lifetime, slice and generic annotation). `name` is the
    formal parameter name. Both are kept verbatim so the template can
    render `data: &[u8]` correctly.
    """

    type: str
    name: str


@dataclass(frozen=True)
class RustEntryPoint:
    """A parsed Rust function signature ready for template rendering."""

    function_name: str
    return_type: str
    params: list[RustParam] = field(default_factory=list)
    module_path: str | None = None
    source_path: str = ""


# ---------------------------------------------------------------------------
# Comment-aware preprocessing
# ---------------------------------------------------------------------------


def _strip_comments(text: str) -> str:
    """Drop // line comments and /* ... */ block comments.

    Done as a pre-pass so a commented-out function declaration cannot be
    picked up as a real declaration. The matching is non-greedy across
    lines for /* ... */ to handle the multi-line shape.

    This intentionally does NOT understand string literals or raw strings
    (`r"..."` / `r#"..."#`) — so a /* inside a string would be
    mis-stripped. None of our M5.2 fixtures contain that pathological
    case. Doc comments (///, //!) are treated like //.
    """
    # /* ... */ block comments (non-greedy across lines).
    # Note: Rust nested block comments (/* /* */ */) aren't handled.
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    out_lines: list[str] = []
    for line in text.splitlines():
        # Strip // line comments (whole-line and inline-trailing). Catches
        # ///, //! doc-comment forms too — fine, those are not declarations.
        if "//" in line:
            line = line.split("//", 1)[0]
        out_lines.append(line.rstrip())
    return "\n".join(out_lines)


# ---------------------------------------------------------------------------
# Module-path discovery
# ---------------------------------------------------------------------------


_MOD_DECL_RE = re.compile(
    r"""
    (?:^|\s)                              # boundary
    (?:pub\s+|pub\(\s*crate\s*\)\s+|pub\(\s*super\s*\)\s+|pub\(\s*self\s*\)\s+)?
    mod\s+
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)
    \s*
    \{                                    # only inline mods carry source
    """,
    re.VERBOSE | re.MULTILINE,
)


def _find_module_path(cleaned_text: str) -> str | None:
    """Return the first inline `mod name { ... }` block name in the cleaned
    source text, or None.

    For M5.2 we record only the innermost-relevant module path heuristically
    — when a fuzz target lives inside `mod parser { pub fn parse(...) }`,
    the extractor reports `module_path="parser"`. Nested module paths
    (`a::b::c`) aren't reconstructed; full path resolution is deferred to
    the syn/rust-analyzer milestone.
    """
    match = _MOD_DECL_RE.search(cleaned_text)
    if not match:
        return None
    return match.group("name")


# ---------------------------------------------------------------------------
# Rust function declaration matching
# ---------------------------------------------------------------------------


# Captures a Rust function declaration. Shape:
#
#   [visibility] [async] [unsafe] [extern "ABI"] fn name(arg_list) [-> return_type] { ... }
#
# We don't require the body — a `;` (trait declaration) also works because
# we only care about signature for harness rendering.
_FN_DECL_RE = re.compile(
    r"""
    (?P<modifiers>
        (?:
            (?:pub(?:\s*\(\s*(?:crate|super|self|in\s+[\w:]+)\s*\))?|
               async|unsafe|const|extern(?:\s+"[^"]+")?)\s+
        )*
    )
    fn\s+
    (?P<name>[A-Za-z_]\w*)                  # function name
    \s*
    \(
    (?P<args>[^)]*)                         # arg list (no nested parens at M5.2)
    \)
    \s*
    (?:->\s*(?P<rtype>[^{};]+?))?           # optional return type (until body/where)
    \s*
    (?:where\s+[^{;]+?)?                    # optional where-clause (consumed; not parsed)
    \s*
    (?:\{|;)
    """,
    re.VERBOSE,
)


def _split_args(arg_list: str) -> list[RustParam]:
    """Split a Rust arg list into RustParam(type, name) entries.

    Naive comma split — fine for the M5.2 targets. Rust uses `name: Type`
    pairs (or `&self`, `&mut self` for methods, which we surface as
    type=`&self` name=""). The implicit self receivers in `impl` blocks
    are dropped from the param list before rendering the cargo-fuzz
    closure (the closure only sees `data: &[u8]`).

    Note that `&[u8]` doesn't contain a comma; if a real target has
    `(a: Foo<Bar, Baz>)` as a param type, this splitter will need to be
    made bracket-aware (deferred).
    """
    params: list[RustParam] = []
    raw = arg_list.strip()
    if not raw:
        return params
    # Naive split for v0; we don't have comma-bearing generics in fixtures.
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        # Receiver shapes: `self`, `&self`, `&mut self`.
        if token in ("self", "&self", "&mut self"):
            params.append(RustParam(type=token, name=""))
            continue
        # Standard form: `name: Type`. Split on the FIRST colon; the type
        # may contain `::` (path), so we deliberately don't use rpartition.
        if ":" in token:
            name_part, _, type_part = token.partition(":")
            params.append(
                RustParam(
                    type=type_part.strip(),
                    name=name_part.strip(),
                )
            )
            continue
        # No colon — anonymous or shorthand. Type-only param.
        params.append(RustParam(type=token, name=""))
    return params


def _normalise_return_type(raw: str | None) -> str:
    """Return a clean return-type spelling.

    Rust functions without `-> Type` return `()` (unit). The extractor
    surfaces that explicitly so the template / caller doesn't need
    special-casing.

    Trailing whitespace / trailing `where`-keyword artifacts are stripped.
    """
    if raw is None:
        return "()"
    rtype = raw.strip()
    # A loose strip of a leaked `where` keyword (the regex consumes it but
    # if the user wrote `fn f() -> i32 where T: Foo { ... }` the regex's
    # rtype group could include `i32 ` before the where-clause kicked in.
    # Drop any trailing token after the first whitespace-delimited type
    # only if the rest looks like a where-clause artifact.
    return rtype


def extract_from_source_text(
    source_text: str,
    function_name: str,
    source_path: str = "",
) -> RustEntryPoint:
    """Find `function_name` in `source_text` and return its RustEntryPoint.

    Raises RustEntryPointNotFoundError if the function is absent (or only
    appears inside comments).
    """
    cleaned = _strip_comments(source_text)
    module_path = _find_module_path(cleaned)

    for match in _FN_DECL_RE.finditer(cleaned):
        if match.group("name") != function_name:
            continue
        rtype = _normalise_return_type(match.group("rtype"))
        params = _split_args(match.group("args"))
        return RustEntryPoint(
            function_name=function_name,
            return_type=rtype,
            params=params,
            module_path=module_path,
            source_path=source_path,
        )

    raise RustEntryPointNotFoundError(
        f"function {function_name!r} not found in Rust source text "
        f"(searched {len(source_text)} chars, source_path={source_path!r})"
    )


__all__ = [
    "RustEntryPoint",
    "RustEntryPointNotFoundError",
    "RustParam",
    "extract_from_source_text",
]
