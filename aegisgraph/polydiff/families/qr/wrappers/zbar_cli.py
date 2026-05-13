"""zbar_cli wrapper — invokes `zbarimg` on witness bytes.

A thin Python CLI mirroring the ZBar `zbarimg` decoder. Reads QR image
bytes (e.g. PNG/JPEG) on stdin and writes one JSON line to stdout
matching schema/fact-vector-qr.schema.json.

When the ZBar binary is not available on PATH (the most common case in
the devcontainer baseline), `run()` returns a crash envelope with
`binary_missing=true` and `decode_outcome.status='parse_error'`.

Historical anchor: ZBar and ZXing have historically disagreed on
structured-append symbol ordering, kanji-mode interpretation, and ECI
charset handling — same QR symbol, different decoded payload.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It decodes
local QR image bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "zbarimg"
_PROFILE = "zbar_cli"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run zbarimg on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
