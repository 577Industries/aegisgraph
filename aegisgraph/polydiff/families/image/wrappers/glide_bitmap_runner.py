"""Glide bitmap-decoder wrapper (JVM).

Invokes the JVM-side runner JAR `glide_bitmap_runner.jar` which decodes
the witness via Glide's bitmap pipeline (the same path Signal Android
uses through `SignalAttachment.requireBitmap`). When `java` or the JAR is
absent in the current environment, returns a crash envelope with
`binary_missing=true` and `decode_outcome.status=crash`.

This is the JVM-bindings counterpart of libwebp_cli: same fact-vector
schema, different decoder implementation. The diff engine compares them
input-by-input to surface JVM-vs-native disagreements (which historically
include the entire libwebp class because Glide falls back to libwebp).
"""

from __future__ import annotations

from typing import Any

from ._dispatch import dispatch


# The JVM runner is invoked through `java -jar <jar>`; the dispatch layer
# treats the first argv element as the binary name. We use `java` so
# FileNotFoundError fires the same way when the JVM is absent. The JAR
# path is the first extra arg (-jar <jar>).
_BINARY = "java"
_PROFILE = "glide_bitmap"
_EXTRA_ARGS = ["-jar", "glide_bitmap_runner.jar"]


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Run glide_bitmap_runner.jar on `witness_bytes`. Always returns a fact-vector."""
    return dispatch(
        profile=_PROFILE,
        binary=_BINARY,
        extra_args=list(_EXTRA_ARGS),
        witness_bytes=witness_bytes,
        input_id=input_id,
    )


__all__ = ["run"]
