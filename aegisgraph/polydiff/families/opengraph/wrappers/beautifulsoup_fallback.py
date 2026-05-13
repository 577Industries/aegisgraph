"""beautifulsoup_fallback wrapper — generic html5lib + bs4 cross-check.

Thin Python CLI around BeautifulSoup4 + html5lib that extracts the same
OG / Twitter Card / canonical-URL meta tags as the other wrappers but via
a generic HTML parser. Acts as the WHATWG-URL-conformant counter-party in
disagreement detection: where Facebook's crawler resolves a relative URL
its own way, bs4+html5lib reflects what a standards-conformant client
would see.

Reads HTML bytes on stdin; writes one JSON line to stdout matching
schema/fact-vector-opengraph.schema.json.

When `bs4_og_extractor` is not on PATH (the CLI binary is not in
pyproject.toml — bs4 + html5lib themselves may be), `run()` returns a
crash envelope with `binary_missing=true`. Tests mock subprocess output
deterministically.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It parses local
HTML strings only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "bs4_og_extractor"
_PROFILE = "beautifulsoup_fallback"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run bs4_og_extractor on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
