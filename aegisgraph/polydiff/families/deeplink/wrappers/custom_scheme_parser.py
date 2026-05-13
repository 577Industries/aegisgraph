"""custom_scheme_parser wrapper — proprietary scheme handling.

A thin Python CLI for proprietary SMA scheme handlers (e.g. `sgnl://`,
`signal://`, `element://`). Mirrors the in-app deeplink router's URI
parser semantics: how the SMA *itself* interprets a proprietary-scheme
URI's host/path/query, including any platform-specific normalization.
Reads URI bytes on stdin and writes one JSON line to stdout matching
schema/fact-vector-deeplink.schema.json.

When the parser binary is not available (the bundled SMA deeplink
parser CLI is not part of this repo's build), `run()` returns a crash
envelope with `binary_missing=true` and
`decode_outcome.status='parse_error'`.

Historical anchor: proprietary-scheme URIs (e.g.
`sgnl://chat/../..//system/`) where the path component admits
traversal — a documented deeplink-traversal bug class. The corpus
pins this divergence by SHA-256.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It parses local
URI bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "custom_scheme_parser"
_PROFILE = "custom_scheme_parser"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run custom_scheme_parser on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
