"""protoc_gogofaster_stub wrapper — stub for the gogo-protobuf decoder.

gogo-protobuf is a Go codegen toolchain that has historically diverged
from google-protobuf on unknown-field handling and oneof ambiguity. The
Python stub always returns a binary_missing envelope; the Go toolchain
is not part of the Python devcontainer baseline.

The stub is preserved in the family because gogo-protobuf vs
google-protobuf disagreement is the canonical unknown-field-handling
bug class (MEDIUM-HIGH). The corpus pins this divergence at
`anchor_proto_unknown_field_handling` so the diff engine can show the
disagreement shape using synthesized fact-vectors during regression
runs.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It decodes
local protobuf wire-format bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import stub_envelope


_PROFILE = "protoc_gogofaster_stub"
_FORMAT_KIND = "protobuf"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Always return a binary_missing envelope (stub)."""
    return stub_envelope(
        profile=_PROFILE,
        input_id=input_id,
        format_kind=_FORMAT_KIND,
        reason="protoc_gogofaster_stub: gogo-protobuf Go toolchain not available in Python devcontainer",
    )


__all__ = ["run"]
