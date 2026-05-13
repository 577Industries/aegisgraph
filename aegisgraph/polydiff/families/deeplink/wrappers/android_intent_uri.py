"""android_intent_uri wrapper — invokes `android_intent_parser` on witness bytes.

A thin Python CLI mirroring Android's `Intent.parseUri()` semantics:
parses `intent://` URIs and extracts the action, category, host, path,
declared permissions, and intent extras encoded in the fragment.
Reads URI bytes on stdin and writes one JSON line to stdout matching
schema/fact-vector-deeplink.schema.json.

When the parser binary/toolchain is not available (the Android SDK is
not part of the devcontainer baseline), `run()` returns a crash
envelope with `binary_missing=true` and
`decode_outcome.status='parse_error'`.

Historical anchor: Android intent URIs that, when parsed by
Intent.parseUri, produce an Intent action matching a non-declared
filter — leading to silent-export risk (the Android intent-confusion
bug class). The corpus pins this divergence by SHA-256.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It parses local
URI bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "android_intent_parser"
_PROFILE = "android_intent_uri"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run android_intent_parser on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
