"""Coil decoder wrapper (JVM).

Invokes the JVM-side runner JAR `coil_decoder_runner.jar` which decodes
the witness via Coil's image pipeline (the path Element X uses through
`MediaRepository.fetchAttachment`). When `java` or the JAR is absent in
the current environment, returns a crash envelope with
`binary_missing=true` and `decode_outcome.status=crash`.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


_BINARY = "java"
_PROFILE = "coil_decoder"
_EXTRA_ARGS = ["-jar", "coil_decoder_runner.jar"]


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run coil_decoder_runner.jar on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=list(_EXTRA_ARGS),
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
