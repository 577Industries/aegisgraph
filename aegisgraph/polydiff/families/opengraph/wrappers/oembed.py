"""oembed wrapper — invokes `oembed_parser` on witness bytes.

A thin Python CLI parsing oEmbed JSON/XML provider responses. Reads
response bytes on stdin and writes one JSON line to stdout matching
schema/fact-vector-opengraph.schema.json.

Historical anchor: when OG metadata and oEmbed provider responses point
to different canonical URLs, downstream consumers picked one or the
other inconsistently — and the attacker controlled the one downstream
trusted. The corpus pins this divergence by SHA-256.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. The oEmbed
response payload is supplied on stdin as a local string.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "oembed_parser"
_PROFILE = "oembed"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run oembed_parser on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
