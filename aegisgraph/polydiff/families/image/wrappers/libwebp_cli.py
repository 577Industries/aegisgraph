"""libwebp wrapper — invokes `libwebp_dec_cli` on the witness bytes.

The binary (a thin Clang-built CLI around `WebPDecode*`) reads image bytes
on stdin and writes a single JSON line to stdout matching
schema/fact-vector-image.schema.json. When the binary is absent in the
current environment (CI without libwebp installed), `run()` returns a
crash envelope with `binary_missing=true` and `decode_outcome.status =
crash`.

CVE-2023-4863 historical reference: heap buffer overflow in
BuildHuffmanTable() reachable via VP8L (lossless) decode. Fixed in libwebp
v1.3.2. Anchored in polydiff/families/image/regression/corpus.json by
SHA-256; the actual witness is at reprochain/corpora-private/ and is
NEVER referenced from this code path.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "libwebp_dec_cli"
_PROFILE = "libwebp"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run libwebp_dec_cli on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
