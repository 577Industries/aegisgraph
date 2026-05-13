"""protoc_python wrapper — invokes `protoc_python_decode` on witness bytes.

A thin Python CLI mirroring the protoc + google.protobuf python decoder.
Reads binary wire-format payload bytes on stdin and writes one JSON
line to stdout matching schema/fact-vector-proto.schema.json.

When the protoc + google.protobuf python decoder binary is not
available on PATH (the most common case in the devcontainer baseline),
`run()` returns a crash envelope with `binary_missing=true` and
`decode_outcome.status='parse_error'`.

Historical anchor: google-protobuf has historically diverged from
gogo-protobuf on unknown-field handling and oneof ambiguity. The
corpus pins this divergence by SHA-256.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It decodes
local protobuf wire-format bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "protoc_python_decode"
_PROFILE = "protoc_python"
_FORMAT_KIND = "protobuf"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run protoc_python_decode on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        format_kind=_FORMAT_KIND,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
