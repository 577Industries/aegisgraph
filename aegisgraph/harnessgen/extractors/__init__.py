"""Native + JVM + Rust entrypoint extractors.

At M3.1 the scaffold shipped `native_entrypoint` — a regex-based parser
that pulls function signatures out of C/C++ header text. M5.1 adds
`jvm_entrypoint` — a regex+comment-aware parser for Java and Kotlin
method declarations, used by the Jazzer template renderer to wire the
first JVM harness (Signal LinkPreviewUtil.findValidPreviewUrls).

Full Clang AST and Soot / Eclipse JDT integrations are deferred to a
later milestone; the regex extractors handle the canonical shapes called
out in Asemarefactor.md (lines 168-186 for JVM, 215-225 for native).
"""

from __future__ import annotations
