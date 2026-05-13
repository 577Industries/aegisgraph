"""apple_vision_stub wrapper — stub for the Apple Vision QR detector.

The Apple Vision framework's VNDetectBarcodesRequest is only available on
macOS / iOS. On Linux devcontainers this wrapper unconditionally returns
a binary_missing envelope; the diff engine still emits the cross-impl
disagreement (Apple Vision absence shows up as a one-ok-one-parse_error
divergence against ZXing or ZBar when those binaries are present).

When the host platform is non-macOS, returning binary_missing is the
canonical signal — the dispatcher's `stub_envelope` builds the
schema-valid envelope directly without invoking subprocess.run.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It decodes local
QR image bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import stub_envelope


_PROFILE = "apple_vision_stub"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Always return a binary_missing envelope (stub)."""
    return stub_envelope(
        profile=_PROFILE,
        input_id=input_id,
        reason="apple_vision_stub: Apple Vision framework not available off-macOS",
    )


__all__ = ["run"]
