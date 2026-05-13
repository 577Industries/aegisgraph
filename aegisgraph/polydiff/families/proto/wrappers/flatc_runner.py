"""flatc_runner wrapper — invokes `flatc` on witness bytes.

A thin Python CLI mirroring the FlatBuffer `flatc` decoder. Reads
binary FlatBuffer payload bytes on stdin and writes one JSON line to
stdout matching schema/fact-vector-proto.schema.json.

When the FlatBuffer `flatc` binary is not available on PATH (the most
common case in the devcontainer baseline), `run()` returns a crash
envelope with `binary_missing=true` and
`decode_outcome.status='parse_error'`.

Historical anchor: FlatBuffer offset overflow has been documented as a
class of disagreement where one decoder accepts an out-of-range offset
silently while another rejects it; the crash + ok pairing surfaces as
HIGH triage.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It decodes
local FlatBuffer wire-format bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "flatc"
_PROFILE = "flatc_runner"
_FORMAT_KIND = "flatbuffer"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run flatc on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        format_kind=_FORMAT_KIND,
        extra_args=None,
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
