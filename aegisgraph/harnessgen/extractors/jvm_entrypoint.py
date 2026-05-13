"""Parse a Java/Kotlin source file to extract a named method signature.

This is the M5.1 regex+comment-aware JVM extractor. It is heuristic — full
Soot / Eclipse JDT integration is deferred to a later milestone. The
contract is intentionally narrow:

  given the text of a Java or Kotlin source file and a method name, return
  a JvmEntryPoint(method_name, return_type, params, declaring_class,
  source_path).

The extractor handles the Signal LinkPreviewUtil shape (Java):

    public static List<Link> findValidPreviewUrls(String text) {
        ...
    }

and the Kotlin companion-object form:

    companion object {
        fun findValidPreviewUrls(text: String): List<Link> {
            ...
        }
    }

It deliberately does NOT handle:
  * annotations on the method line (caller pre-strips, or the regex sees
    them as a fail-and-skip) — none of our M5.1 targets have line-leading
    annotations on the method we fuzz.
  * generic-bounded type parameters on the method (`<T extends Foo>`)
    are accepted only as part of the return type; method-level generics
    in declaration position are not parsed.
  * varargs (`String...`) — caller can fall back to a hand-written
    JvmEntryPoint.

Anything unparseable raises JvmEntryPointNotFoundError; the caller is
expected to retry with a hand-written JvmEntryPoint or to extend the
extractor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


class JvmEntryPointNotFoundError(LookupError):
    """Raised when the named method is not found in the source text.

    Fail-closed: the caller must NOT proceed with a guessed signature.
    The Jazzer template depends on the parsed types to render the call
    correctly; a wrong return type or missing param produces invalid
    Java.
    """


@dataclass(frozen=True)
class JvmParam:
    """One parameter of a parsed JVM method signature.

    `type` is the Java/Kotlin type spelling as it appears in source
    (including generic argument annotation). `name` is the formal
    parameter name. Both are kept verbatim so the template can render
    `String text` vs `text: String` correctly per source language.
    """

    type: str
    name: str


@dataclass(frozen=True)
class JvmEntryPoint:
    """A parsed JVM method signature ready for template rendering."""

    method_name: str
    return_type: str
    params: list[JvmParam] = field(default_factory=list)
    declaring_class: str | None = None
    source_path: str = ""


# ---------------------------------------------------------------------------
# Comment-aware preprocessing
# ---------------------------------------------------------------------------


def _strip_comments(text: str) -> str:
    """Drop // line comments and /* ... */ block comments.

    Done as a pre-pass so a commented-out method declaration cannot be
    picked up as a real declaration. The matching is non-greedy across
    lines for /* ... */ to handle the multi-line shape.

    This is intentionally simple — it does NOT understand string literals,
    so a /* inside a string would be mis-stripped. None of our M5.1
    fixtures contain that pathological case.
    """
    # /* ... */ block comments (non-greedy across lines).
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    out_lines: list[str] = []
    for line in text.splitlines():
        # Strip // line comments (whole-line and inline-trailing).
        if "//" in line:
            line = line.split("//", 1)[0]
        out_lines.append(line.rstrip())
    return "\n".join(out_lines)


# ---------------------------------------------------------------------------
# Class-name discovery (Java + Kotlin)
# ---------------------------------------------------------------------------


_CLASS_DECL_RE = re.compile(
    r"""
    (?:^|\s)                              # boundary
    (?:public\s+|private\s+|internal\s+|abstract\s+|final\s+|open\s+|sealed\s+)*
    class\s+
    (?P<name>[A-Z][A-Za-z0-9_]*)
    """,
    re.VERBOSE | re.MULTILINE,
)


def _find_declaring_class(cleaned_text: str) -> str | None:
    """Return the first top-level class name in the cleaned source text.

    For M5.1 we assume a single top-level class per file, which holds for
    all our entry-point targets. Nested classes are ignored — the method
    we fuzz is always on the outer class (Signal LinkPreviewUtil's nested
    `Link` is a data type, not an entry point).
    """
    match = _CLASS_DECL_RE.search(cleaned_text)
    if not match:
        return None
    return match.group("name")


# ---------------------------------------------------------------------------
# Java method declaration matching
# ---------------------------------------------------------------------------


# Captures a Java-style method declaration.
#
# Shape:  [modifiers] return_type name ( arg_list ) [throws ...] { ... }
# We don't require the body — a `;` (abstract) also works because we only
# care about signature for harness rendering.
_JAVA_METHOD_RE = re.compile(
    r"""
    (?P<modifiers>
        (?:
            (?:public|private|protected|static|final|abstract|synchronized|
               native|strictfp|default)\s+
        )*
    )
    (?P<rtype>[\w.<>,\s\[\]?]+?)            # return type (lazy, generics-aware)
    \s+
    (?P<name>[a-zA-Z_]\w*)                  # method name
    \s*
    \(
    (?P<args>[^)]*)                         # arg list (no nested parens at M5.1)
    \)
    \s*
    (?:throws\s+[\w.,\s]+)?                 # optional throws clause
    \s*
    (?:\{|;)
    """,
    re.VERBOSE,
)


# Captures a Kotlin-style method declaration.
#
# Shape:  [modifiers] fun name ( arg_list ) [: return_type] [{ ... } | = expr]
_KOTLIN_FUN_RE = re.compile(
    r"""
    (?P<modifiers>
        (?:
            (?:public|private|internal|protected|open|final|abstract|
               override|inline|operator|infix|tailrec|suspend)\s+
        )*
    )
    fun\s+
    (?P<name>[a-zA-Z_]\w*)                  # method name
    \s*
    \(
    (?P<args>[^)]*)                         # arg list
    \)
    \s*
    (?::\s*(?P<rtype>[\w.<>,\s\[\]?]+?))?   # optional return type
    \s*
    (?:\{|=)
    """,
    re.VERBOSE,
)


def _split_java_args(arg_list: str) -> list[JvmParam]:
    """Split a Java arg list into Param(type, name) entries.

    Naive comma split — fine for the M5.1 targets. Note that
    `List<Link>` doesn't contain a comma in our fixtures; if a real target
    has `Map<String, Integer>` as a param type, this splitter will need
    to be made bracket-aware (deferred).
    """
    args: list[JvmParam] = []
    raw = arg_list.strip()
    if not raw:
        return args
    # Naive split for v0; we don't have comma-bearing generics in fixtures.
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        # Trailing identifier is the param name; everything else is the type.
        m = re.match(r"^(.*?)([\s])(\w+)\s*$", token)
        if not m:
            args.append(JvmParam(type=token, name=""))
            continue
        type_part = m.group(1).strip()
        name_part = m.group(3)
        args.append(JvmParam(type=type_part, name=name_part))
    return args


def _split_kotlin_args(arg_list: str) -> list[JvmParam]:
    """Split a Kotlin arg list into Param(type, name) entries.

    Kotlin shape:  name: Type, name2: Type2, ...
    """
    args: list[JvmParam] = []
    raw = arg_list.strip()
    if not raw:
        return args
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if ":" not in token:
            args.append(JvmParam(type=token, name=""))
            continue
        name_part, _, type_part = token.partition(":")
        args.append(
            JvmParam(type=type_part.strip(), name=name_part.strip())
        )
    return args


def _is_kotlin_source(source_path: str, source_text: str) -> bool:
    """Cheap detect: trailing extension OR the `fun ` keyword presence."""
    if source_path.endswith(".kt") or source_path.endswith(".kts"):
        return True
    # Kotlin's `fun ` token is a strong signal; Java doesn't use it.
    return bool(re.search(r"\bfun\s+\w+\s*\(", source_text))


def extract_from_source_text(
    source_text: str,
    method_name: str,
    source_path: str = "",
) -> JvmEntryPoint:
    """Find `method_name` in `source_text` and return its JvmEntryPoint.

    Raises JvmEntryPointNotFoundError if the method is absent (or only
    appears inside comments).
    """
    cleaned = _strip_comments(source_text)
    declaring_class = _find_declaring_class(cleaned)

    if _is_kotlin_source(source_path, cleaned):
        # Try Kotlin matcher first.
        for match in _KOTLIN_FUN_RE.finditer(cleaned):
            if match.group("name") != method_name:
                continue
            rtype_raw = match.group("rtype") or "Unit"
            params = _split_kotlin_args(match.group("args"))
            return JvmEntryPoint(
                method_name=method_name,
                return_type=rtype_raw.strip(),
                params=params,
                declaring_class=declaring_class,
                source_path=source_path,
            )
        # Fall through to Java matcher just in case the file is mixed.

    for match in _JAVA_METHOD_RE.finditer(cleaned):
        if match.group("name") != method_name:
            continue
        # Filter out things that look like a constructor (return type == class name)
        # or a control-flow keyword (`if`, `while`, etc).
        rtype_raw = match.group("rtype").strip()
        if rtype_raw in {"if", "while", "for", "switch", "return", "throw"}:
            continue
        params = _split_java_args(match.group("args"))
        return JvmEntryPoint(
            method_name=method_name,
            return_type=rtype_raw,
            params=params,
            declaring_class=declaring_class,
            source_path=source_path,
        )

    raise JvmEntryPointNotFoundError(
        f"method {method_name!r} not found in source text "
        f"(searched {len(source_text)} chars, source_path={source_path!r})"
    )


__all__ = [
    "JvmEntryPoint",
    "JvmEntryPointNotFoundError",
    "JvmParam",
    "extract_from_source_text",
]
