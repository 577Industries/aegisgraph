"""Shared subprocess dispatch for image-family wrappers.

Each per-implementation wrapper (libwebp_cli, libavif_cli, libheif_cli,
glide_bitmap_runner, coil_decoder_runner) declares its binary name + argv
and calls into `dispatch()`. The dispatcher:

  1. Invokes the binary with witness bytes on stdin.
  2. Parses one JSON line from stdout (per the wrapper subprocess contract).
  3. Returns the parsed dict on success.
  4. On FileNotFoundError, non-zero exit, timeout, or malformed JSON,
     returns a `_crash_envelope`-equivalent fact-vector with
     decode_outcome.status='crash' (and binary_missing=true when the
     binary itself is absent).

The envelope always validates against schema/fact-vector-image.schema.json.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


SUBPROCESS_TIMEOUT_S = 10.0  # generous; cold-start of jvm/native is slow


def dispatch(
    *,
    profile: str,
    binary: str,
    extra_args: list[str] | None,
    witness_bytes: bytes,
    input_id: str,
) -> dict[str, Any]:
    """Run an image-family wrapper subprocess. Always returns a fact-vector.

    Args:
      profile:       Wrapper id (libwebp / libavif / libheif / ...).
      binary:        Executable name as it must appear on PATH.
      extra_args:    Optional argv tail (e.g. ["--input-id", input_id]).
      witness_bytes: Image bytes piped to the binary on stdin.
      input_id:      Cross-impl identity key for the diff engine.

    Returns:
      A dict matching schema/fact-vector-image.schema.json.
    """
    argv: list[str] = [binary, "--input-id", input_id]
    if extra_args:
        argv.extend(extra_args)

    try:
        proc = subprocess.run(
            argv,
            input=witness_bytes,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT_S,
            check=False,
        )
    except FileNotFoundError:
        return _crash_envelope(
            profile=profile,
            input_id=input_id,
            reason=f"wrapper binary missing: {binary}",
            binary_missing=True,
        )
    except subprocess.TimeoutExpired:
        return _crash_envelope(
            profile=profile,
            input_id=input_id,
            reason="wrapper subprocess timeout",
            binary_missing=False,
        )

    if proc.returncode != 0:
        return _crash_envelope(
            profile=profile,
            input_id=input_id,
            reason=(
                f"wrapper exit code {proc.returncode}: "
                + proc.stderr.decode("utf-8", "replace")[:200]
            ),
            binary_missing=False,
            status="decode_error",
        )

    line = proc.stdout.decode("utf-8", "replace").strip()
    if not line:
        return _crash_envelope(
            profile=profile,
            input_id=input_id,
            reason="wrapper produced no stdout",
            binary_missing=False,
        )
    try:
        envelope = json.loads(line.splitlines()[0])
    except json.JSONDecodeError as exc:
        return _crash_envelope(
            profile=profile,
            input_id=input_id,
            reason=f"wrapper produced invalid JSON: {exc}",
            binary_missing=False,
        )

    # Ensure required identity keys are populated (the binary may omit them).
    envelope.setdefault("input_id", input_id)
    envelope.setdefault("parser_profile", profile)
    # Ensure every required axis is present; the schema requires explicit
    # nulls rather than missing keys.
    for axis in (
        "dimensions",
        "color_space",
        "alpha_premultiplied",
        "frame_count",
        "first_pixel_rgba",
    ):
        envelope.setdefault(axis, None)
    envelope.setdefault("decode_outcome", {"status": "ok", "bytes_out": 0})
    envelope.setdefault("parser_warnings", [])
    return envelope


def _crash_envelope(
    *,
    profile: str,
    input_id: str,
    reason: str,
    binary_missing: bool,
    status: str = "crash",
) -> dict[str, Any]:
    """Return the canonical crash envelope for the image fact-vector schema.

    A wrapper that cannot produce a real decode (binary absent, segfault,
    malformed JSON) emits this shape. The diff engine treats `crash` as a
    first-class disagreement axis value — Asemarefactor.md line 88 routes
    a one-crash-one-ok divergence to HIGH triage automatically.
    """
    return {
        "input_id": input_id,
        "parser_profile": profile,
        "schema_version": "v1.0",
        "binary_missing": bool(binary_missing),
        "errors": [reason],
        "dimensions": None,
        "color_space": None,
        "alpha_premultiplied": None,
        "frame_count": None,
        "first_pixel_rgba": None,
        "decode_outcome": {"status": status, "bytes_out": 0},
        "parser_warnings": ["wrapper crash recorded as a Finding"],
    }


__all__ = ["dispatch", "_crash_envelope", "SUBPROCESS_TIMEOUT_S"]
