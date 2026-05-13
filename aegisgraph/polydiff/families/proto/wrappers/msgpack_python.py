"""msgpack_python wrapper — invokes `msgpack_python_decode` on witness bytes.

A thin Python CLI mirroring the msgpack-python parser. Reads binary
msgpack payload bytes on stdin and writes one JSON line to stdout
matching schema/fact-vector-proto.schema.json.

When the msgpack python decoder binary is not available on PATH (the
most common case in the devcontainer baseline), `run()` returns a
crash envelope with `binary_missing=true` and
`decode_outcome.status='parse_error'`.

Historical anchor: msgpack ext-type collision has been documented as a
class of disagreement where two decoders interpret the same ext-type
tag differently — e.g. a timestamp vs raw bytes interpretation.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It decodes
local msgpack wire-format bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "msgpack_python_decode"
_PROFILE = "msgpack_python"
_FORMAT_KIND = "msgpack"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run msgpack_python_decode on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        format_kind=_FORMAT_KIND,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
