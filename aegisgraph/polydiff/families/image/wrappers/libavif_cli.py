"""libavif wrapper — invokes `libavif_dec_cli` on the witness bytes.

Thin CLI around `avifDecoderRead*`. Stdin: AVIF bytes. Stdout: one JSON
line matching schema/fact-vector-image.schema.json. Binary-absent
envelope per the shared dispatch contract.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "libavif_dec_cli"
_PROFILE = "libavif"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run libavif_dec_cli on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
