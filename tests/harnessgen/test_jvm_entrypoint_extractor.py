"""JVM entrypoint extractor: parses a Java/Kotlin source snippet and returns
a structured representation of a public method signature usable by the
Jazzer template.

The extractor is heuristic (regex+comment-aware) at M5.1 — full Soot /
Eclipse JDT integration is deferred. The contract that must hold at M5.1:

  * Given Java/Kotlin source text containing a method declaration, the
    extractor returns a `JvmEntryPoint` dataclass with:
      - method_name: identifier
      - return_type: e.g. "List<Link>" (Java) or "List<Link>" (Kotlin form)
      - params: list of (type, name) tuples
      - declaring_class: optional containing class name
      - source_path: passthrough for traceability
  * Unknown method names raise `JvmEntryPointNotFoundError`.
  * Multiple candidates in a single file find the named one only.
  * Comments (//, /* ... */, ///, /** ... */) are stripped before matching
    so a method commented-out is not picked up as a real declaration.
  * Methods only inside Kotlin `companion object` / static contexts are
    parsed identically — Java statics work via the `static` modifier too.

This test exercises only the extractor surface; no compilation, no
filesystem reads (input is a string).
"""

from __future__ import annotations

import pytest

from aegisgraph.harnessgen.extractors.jvm_entrypoint import (
    JvmEntryPoint,
    JvmEntryPointNotFoundError,
    extract_from_source_text,
)


SIGNAL_LINK_PREVIEW_JAVA = """
// excerpt of Signal Android LinkPreviewUtil.java (GPL-3.0)
package org.thoughtcrime.securesms.linkpreview;

import java.util.List;
import java.util.regex.Pattern;

public class LinkPreviewUtil {
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\\s]+");

    /**
     * Find valid preview URLs in the supplied text.
     *
     * @param text source text potentially containing URLs
     * @return list of validated Link instances; empty list if none found
     */
    public static List<Link> findValidPreviewUrls(String text) {
        // implementation omitted
        return null;
    }

    // public static void notARealMethod(String s) {  // commented-out; must be ignored
    /* public static int alsoCommentedOut(int n) {
           return n;
       } */

    public static class Link {
        public final String url;
        public Link(String url) { this.url = url; }
    }
}
"""


SIGNAL_LINK_PREVIEW_KOTLIN = """
// excerpt of Signal Android LinkPreviewUtil.kt (hypothetical Kotlin form)
package org.thoughtcrime.securesms.linkpreview

class LinkPreviewUtil {
    companion object {
        // Public method we want to fuzz.
        fun findValidPreviewUrls(text: String): List<Link> {
            return emptyList()
        }
    }
}
"""


def test_extract_signal_link_preview_java_returns_entrypoint() -> None:
    entry = extract_from_source_text(
        source_text=SIGNAL_LINK_PREVIEW_JAVA,
        method_name="findValidPreviewUrls",
        source_path="LinkPreviewUtil.java",
    )
    assert isinstance(entry, JvmEntryPoint)
    assert entry.method_name == "findValidPreviewUrls"
    assert entry.source_path == "LinkPreviewUtil.java"


def test_extract_java_signature_has_string_param() -> None:
    entry = extract_from_source_text(
        source_text=SIGNAL_LINK_PREVIEW_JAVA,
        method_name="findValidPreviewUrls",
        source_path="LinkPreviewUtil.java",
    )
    param_types = [p.type for p in entry.params]
    assert "String" in param_types
    # Param names captured too.
    assert any(p.name == "text" for p in entry.params)


def test_extract_java_return_type_is_list() -> None:
    entry = extract_from_source_text(
        source_text=SIGNAL_LINK_PREVIEW_JAVA,
        method_name="findValidPreviewUrls",
        source_path="LinkPreviewUtil.java",
    )
    assert "List" in entry.return_type


def test_extract_java_declaring_class_captured() -> None:
    entry = extract_from_source_text(
        source_text=SIGNAL_LINK_PREVIEW_JAVA,
        method_name="findValidPreviewUrls",
        source_path="LinkPreviewUtil.java",
    )
    # The extractor records the containing class so the harness can render
    # `LinkPreviewUtil.findValidPreviewUrls(...)`.
    assert entry.declaring_class == "LinkPreviewUtil"


def test_extract_kotlin_signature_resolves() -> None:
    """Kotlin fun keyword + companion object form parses identically."""
    entry = extract_from_source_text(
        source_text=SIGNAL_LINK_PREVIEW_KOTLIN,
        method_name="findValidPreviewUrls",
        source_path="LinkPreviewUtil.kt",
    )
    assert entry.method_name == "findValidPreviewUrls"
    # Kotlin signature carries Kotlin types; we accept the raw spelling.
    assert any("String" in p.type for p in entry.params)


def test_extract_unknown_method_raises() -> None:
    with pytest.raises(JvmEntryPointNotFoundError):
        extract_from_source_text(
            source_text=SIGNAL_LINK_PREVIEW_JAVA,
            method_name="DefinitelyNotAMethod",
            source_path="LinkPreviewUtil.java",
        )


def test_extract_skips_commented_out_methods() -> None:
    """A method whose declaration sits inside a //-line comment or a
    /* ... */ block must NOT be picked up as a real declaration. The Signal
    fixture intentionally includes both shapes to exercise this."""
    with pytest.raises(JvmEntryPointNotFoundError):
        extract_from_source_text(
            source_text=SIGNAL_LINK_PREVIEW_JAVA,
            method_name="notARealMethod",
            source_path="LinkPreviewUtil.java",
        )
    with pytest.raises(JvmEntryPointNotFoundError):
        extract_from_source_text(
            source_text=SIGNAL_LINK_PREVIEW_JAVA,
            method_name="alsoCommentedOut",
            source_path="LinkPreviewUtil.java",
        )


def test_extract_picks_named_method_not_first_match() -> None:
    """If a file has multiple public methods, the extractor returns the one
    we asked for, not the first one in source order."""
    multi = """
    package x.y;
    public class C {
        public static int alpha(int n) { return n; }
        public static String beta(String s) { return s; }
    }
    """
    entry = extract_from_source_text(
        source_text=multi,
        method_name="beta",
        source_path="C.java",
    )
    assert entry.method_name == "beta"
    assert "String" in entry.return_type
