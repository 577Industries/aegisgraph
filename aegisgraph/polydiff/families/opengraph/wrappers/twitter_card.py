"""twitter_card wrapper — invokes `twitter_card_parser` on witness bytes.

A thin Python CLI parsing Twitter Card meta tags
(<meta name='twitter:card'>, <meta name='twitter:player'>, etc.). Reads
HTML bytes on stdin and writes one JSON line to stdout matching
schema/fact-vector-opengraph.schema.json.

Historical anchor: `twitter:player` URL fields had inconsistent
sanitization between Twitter's crawler and downstream embedders, leading
to XSS-prone link previews. The corpus pins this divergence by SHA-256.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It parses local
HTML strings only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "twitter_card_parser"
_PROFILE = "twitter_card"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run twitter_card_parser on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
