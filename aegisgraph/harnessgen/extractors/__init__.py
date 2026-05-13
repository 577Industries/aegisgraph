"""Native + JVM + Rust entrypoint extractors.

At M3.1 only `native_entrypoint` ships — a regex-based parser that pulls
function signatures out of C/C++ header text. Full Clang AST integration
is deferred; the regex extractor handles the libwebp shape that Asemarefactor.md
calls out as the M3.1 first target.
"""

from __future__ import annotations
