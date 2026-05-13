"""web_url_fallback wrapper — generic WHATWG-URL cross-check parser.

A thin Python CLI around a WHATWG-URL conformant parser (e.g. cpython's
`urllib.parse` augmented to honor the WHATWG-URL standard, or the
`whatwg-url` package). Acts as the spec-conformant counter-party in
disagreement detection: where Android Intent.parseUri or iOS
NSURLComponents resolve a URI their own way, this wrapper reflects
what a standards-conformant client would see.

Reads URI bytes on stdin; writes one JSON line to stdout matching
schema/fact-vector-deeplink.schema.json. For non-HTTP schemes the
wrapper still returns scheme/host/path/query_params parsed per
RFC 3986; intent_action and intent_category are always null for this
profile.

When `whatwg_url_parser` is not on PATH (a generic Python WHATWG URL
parser CLI is not guaranteed in the devcontainer), `run()` returns a
crash envelope with `binary_missing=true`. Tests mock subprocess
output deterministically.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It parses local
URI bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "whatwg_url_parser"
_PROFILE = "web_url_fallback"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run whatwg_url_parser on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
