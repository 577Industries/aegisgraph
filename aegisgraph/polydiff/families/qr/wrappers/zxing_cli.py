"""zxing_cli wrapper — invokes `zxing_cli` on witness bytes.

A thin Python CLI mirroring the ZXing decoder pipeline. Reads QR image
bytes (e.g. PNG/JPEG) on stdin and writes one JSON line to stdout
matching schema/fact-vector-qr.schema.json.

When the ZXing CLI binary is not available on PATH (the most common
case in the devcontainer baseline), `run()` returns a crash envelope
with `binary_missing=true` and `decode_outcome.status='parse_error'`.

Historical anchor: ZXing's URL extraction has historically diverged
from the iOS Camera URL handler — same QR symbol, different URL
extracted. The corpus pins this divergence by SHA-256.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It decodes
local QR image bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "zxing_cli"
_PROFILE = "zxing_cli"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run zxing_cli on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
