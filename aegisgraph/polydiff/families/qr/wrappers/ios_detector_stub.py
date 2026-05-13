"""ios_detector_stub wrapper — stub for the iOS Camera QR detector.

The iOS Camera URL-handling QR detector is only available on-device
(CIDetector / AVCaptureMetadataOutput). In every off-device context
(CI, devcontainer, macOS dev box) this wrapper unconditionally returns
a binary_missing envelope.

The stub is preserved in the family because the iOS Camera URL handler
has historically diverged from ZXing on URL extraction from the same
QR symbol (URL-in-QR phishing surface). The corpus pins this
divergence at `anchor_qr_apple_camera_url_handler` so the diff engine
can show the disagreement shape using synthesized fact-vectors during
regression runs.

NETWORK CONSTRAINT: this wrapper MUST NOT fetch URLs. It decodes local
QR image bytes only.
"""

from __future__ import annotations

from typing import Any

from ._dispatch import stub_envelope


_PROFILE = "ios_detector_stub"


def run(witness_bytes: bytes, input_id: str) -> dict[str, Any]:
    """Always return a binary_missing envelope (stub)."""
    return stub_envelope(
        profile=_PROFILE,
        input_id=input_id,
        reason="ios_detector_stub: iOS Camera QR detector only available on-device",
    )


__all__ = ["run"]
