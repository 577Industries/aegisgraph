"""facebook_og wrapper — invokes `facebook_og_parser` on witness bytes.

A thin Python CLI around a Facebook-crawler-style Open Graph parser
(e.g. `opengraph-py` or similar). Reads HTML bytes on stdin and writes
one JSON line to stdout matching schema/fact-vector-opengraph.schema.json.

When the parser package is not installed (likely on stock devcontainers),
`run()` returns a crash envelope with `binary_missing=true` and
`decode_outcome.status=crash`.

Historical anchor: Facebook's OG crawler resolved relative URLs against
the crawled page differently from WHATWG-URL conformant downstream
consumers (~2018). The corpus pins this divergence by SHA-256.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It parses local
HTML strings only — never resolves URLs over the network.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "facebook_og_parser"
_PROFILE = "facebook_og"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run facebook_og_parser on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
