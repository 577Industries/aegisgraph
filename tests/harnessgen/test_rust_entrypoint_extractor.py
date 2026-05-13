"""Rust entrypoint extractor: parses a Rust source snippet and returns a
structured representation of a function signature usable by the cargo-fuzz
template.

The extractor is heuristic (regex+comment-aware) at M5.2 — full
syn / rust-analyzer integration is deferred. The contract that must hold at
M5.2:

  * Given Rust source text containing a function declaration, the extractor
    returns a `RustEntryPoint` dataclass with:
      - function_name: identifier
      - return_type: e.g. "Result<MessageType, serde_json::Error>" or "()"
      - params: list of (type, name) tuples
      - module_path: optional containing module path (parsed from `mod` / `pub mod`)
      - source_path: passthrough for traceability
  * Unknown function names raise `RustEntryPointNotFoundError`.
  * Multiple candidates in a single file find the named one only.
  * Comments (//, /// , //!, /* ... */) are stripped before matching so a
    function commented-out is not picked up as a real declaration.
  * The extractor handles `fn`, `pub fn`, `pub(crate) fn`, `async fn`,
    `unsafe fn`, and generic-parameter prefixes like `pub fn foo<T>(...)`.

This test exercises only the extractor surface; no compilation, no
filesystem reads (input is a string).
"""

from __future__ import annotations

import pytest

from aegisgraph.harnessgen.extractors.rust_entrypoint import (
    RustEntryPoint,
    RustEntryPointNotFoundError,
    extract_from_source_text,
)


MATRIX_MESSAGE_TYPE_RUST = """
//! excerpt of matrix-rust-sdk ruma::events::room::message (Apache-2.0)
use serde::{Deserialize, Serialize};

/// MessageType — tagged union of room message variants (text, image, file, ...).
///
/// We fuzz this via serde_json::from_slice in the cargo-fuzz target.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "msgtype")]
pub enum MessageType {
    #[serde(rename = "m.text")]
    Text { body: String },
    #[serde(rename = "m.image")]
    Image { body: String, url: String },
}

impl MessageType {
    /// Deserialize a MessageType from a slice of JSON bytes.
    pub fn from_slice(data: &[u8]) -> Result<MessageType, serde_json::Error> {
        serde_json::from_slice::<MessageType>(data)
    }

    // pub fn deprecated_helper(s: &str) -> i32 {  // commented-out; must be ignored
    /* pub fn also_commented_out(n: u32) -> u32 {
           n + 1
       } */
}
"""


SIMPLE_RUST_FN = """
// Trivial Rust module for parser unit-tests.
pub mod parser {
    pub fn parse(data: &[u8]) -> Option<Vec<u8>> {
        Some(data.to_vec())
    }

    pub async fn fetch(url: &str) -> Result<String, std::io::Error> {
        Ok(String::new())
    }

    pub(crate) fn internal_only(n: i32) -> i32 { n }

    unsafe fn raw_pointer_op(ptr: *const u8) -> u8 { *ptr }
}
"""


def test_extract_matrix_message_type_from_slice_returns_entrypoint() -> None:
    entry = extract_from_source_text(
        source_text=MATRIX_MESSAGE_TYPE_RUST,
        function_name="from_slice",
        source_path="message.rs",
    )
    assert isinstance(entry, RustEntryPoint)
    assert entry.function_name == "from_slice"
    assert entry.source_path == "message.rs"


def test_extract_signature_has_byte_slice_param() -> None:
    entry = extract_from_source_text(
        source_text=MATRIX_MESSAGE_TYPE_RUST,
        function_name="from_slice",
        source_path="message.rs",
    )
    # The MessageType::from_slice signature uses `data: &[u8]`.
    param_types = [p.type for p in entry.params]
    assert any("&[u8]" in t or "u8" in t for t in param_types)
    assert any(p.name == "data" for p in entry.params)


def test_extract_return_type_is_result_message_type() -> None:
    entry = extract_from_source_text(
        source_text=MATRIX_MESSAGE_TYPE_RUST,
        function_name="from_slice",
        source_path="message.rs",
    )
    # Return type spelled `Result<MessageType, serde_json::Error>`.
    assert "Result" in entry.return_type
    assert "MessageType" in entry.return_type


def test_extract_unknown_function_raises() -> None:
    with pytest.raises(RustEntryPointNotFoundError):
        extract_from_source_text(
            source_text=MATRIX_MESSAGE_TYPE_RUST,
            function_name="DefinitelyNotAFunction",
            source_path="message.rs",
        )


def test_extract_skips_commented_out_functions() -> None:
    """A function whose declaration sits inside a //-line comment or a
    /* ... */ block must NOT be picked up as a real declaration. The fixture
    intentionally includes both shapes to exercise this."""
    with pytest.raises(RustEntryPointNotFoundError):
        extract_from_source_text(
            source_text=MATRIX_MESSAGE_TYPE_RUST,
            function_name="deprecated_helper",
            source_path="message.rs",
        )
    with pytest.raises(RustEntryPointNotFoundError):
        extract_from_source_text(
            source_text=MATRIX_MESSAGE_TYPE_RUST,
            function_name="also_commented_out",
            source_path="message.rs",
        )


def test_extract_pub_async_fn_resolves() -> None:
    """`pub async fn` variant parses; the async keyword is a modifier."""
    entry = extract_from_source_text(
        source_text=SIMPLE_RUST_FN,
        function_name="fetch",
        source_path="parser.rs",
    )
    assert entry.function_name == "fetch"
    assert "Result" in entry.return_type


def test_extract_pub_crate_fn_resolves() -> None:
    """`pub(crate) fn` (restricted visibility) parses identically."""
    entry = extract_from_source_text(
        source_text=SIMPLE_RUST_FN,
        function_name="internal_only",
        source_path="parser.rs",
    )
    assert entry.function_name == "internal_only"
    assert entry.return_type == "i32"


def test_extract_unsafe_fn_resolves() -> None:
    """`unsafe fn` (no `pub`) parses; visibility is optional."""
    entry = extract_from_source_text(
        source_text=SIMPLE_RUST_FN,
        function_name="raw_pointer_op",
        source_path="parser.rs",
    )
    assert entry.function_name == "raw_pointer_op"


def test_extract_picks_named_function_not_first_match() -> None:
    """If a file has multiple `pub fn`s, the extractor returns the one we
    asked for, not the first one in source order."""
    multi = """
    pub fn alpha(n: i32) -> i32 { n }
    pub fn beta(s: &str) -> String { s.to_string() }
    """
    entry = extract_from_source_text(
        source_text=multi,
        function_name="beta",
        source_path="multi.rs",
    )
    assert entry.function_name == "beta"
    assert "String" in entry.return_type


def test_extract_unit_return_when_no_arrow() -> None:
    """A Rust fn without `-> Type` returns `()` (unit). The extractor must
    surface that explicitly so the template can render correctly."""
    snippet = """
    pub fn side_effect(n: u32) {
        println!("{}", n);
    }
    """
    entry = extract_from_source_text(
        source_text=snippet,
        function_name="side_effect",
        source_path="x.rs",
    )
    assert entry.return_type == "()"


def test_extract_function_with_no_params() -> None:
    """A nullary fn must yield an empty params list."""
    snippet = """
    pub fn nullary() -> bool { true }
    """
    entry = extract_from_source_text(
        source_text=snippet,
        function_name="nullary",
        source_path="x.rs",
    )
    assert entry.params == []
    assert entry.return_type == "bool"


def test_extract_captures_module_path_optional() -> None:
    """The extractor records the surrounding `mod`/`pub mod` name so the
    cargo-fuzz template can render `path::to::module::function` if needed.
    Absent → None."""
    entry = extract_from_source_text(
        source_text=SIMPLE_RUST_FN,
        function_name="parse",
        source_path="parser.rs",
    )
    # parser module is declared as `pub mod parser { ... }` — must be captured.
    assert entry.module_path == "parser"
