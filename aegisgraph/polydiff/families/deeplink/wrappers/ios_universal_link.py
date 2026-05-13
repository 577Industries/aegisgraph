"""ios_universal_link wrapper — invokes `ios_universal_link_parser`.

A thin Python CLI mirroring iOS NSURL / NSURLComponents semantics:
parses HTTPS URLs treated as iOS universal links and extracts the host,
path, query parameters, and fragment. Reads URI bytes on stdin and
writes one JSON line to stdout matching
schema/fact-vector-deeplink.schema.json.

When the parser binary/toolchain is not available (no iOS toolchain in
the devcontainer baseline), `run()` returns a crash envelope with
`binary_missing=true` and `decode_outcome.status='parse_error'`.

Historical anchor: HTTPS URLs that NSURLComponents parses one way and
the SMA's link-handler parses differently, producing origin-confusion
(the iOS universal-link bug class). The corpus pins this divergence by
SHA-256.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It parses local
URI bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "ios_universal_link_parser"
_PROFILE = "ios_universal_link"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run ios_universal_link_parser on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
