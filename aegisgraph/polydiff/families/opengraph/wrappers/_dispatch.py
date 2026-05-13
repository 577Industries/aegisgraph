"""Shared subprocess dispatch for opengraph-family wrappers.

Each per-implementation wrapper (facebook_og, twitter_card, oembed,
beautifulsoup_fallback) declares its binary name + argv and calls into
`dispatch()`. The dispatcher:

  1. Invokes the binary with witness bytes on stdin.
  2. Parses one JSON line from stdout (per the wrapper subprocess contract).
  3. Returns the parsed dict on success.
  4. On FileNotFoundError, non-zero exit, timeout, or malformed JSON,
     returns a `_crash_envelope`-equivalent fact-vector with
     decode_outcome.status='crash' (and binary_missing=true when the
     binary itself is absent).

The envelope always validates against
schema/fact-vector-opengraph.schema.json.

Mirror of aegisgraph/polydiff/families/image/wrappers/_dispatch.py with
the opengraph axes substituted.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


SUBPROCESS_TIMEOUT_S = 10.0  # generous; cold-start of parsers can be slow

# Required axes from the opengraph fact-vector schema. The dispatch layer
# defaults any axis that the subprocess omitted to None so the resulting
# envelope always validates against the schema.
_REQUIRED_AXES = (
    "og_title",
    "og_image",
    "og_type",
    "og_url",
    "og_video",
    "twitter_card_type",
    "twitter_image",
    "oembed_type",
    "canonical_url",
)


def dispatch(
    *,
    profile: str,
    binary: str,
    extra_args: list[str] | None,
    witness_bytes: bytes,
    input_id: str,
) -> dict[str, Any]:
    """Run an opengraph-family wrapper subprocess. Always returns a fact-vector.

    Args:
      profile:       Wrapper id (facebook_og / twitter_card / oembed / ...).
      binary:        Executable name as it must appear on PATH.
      extra_args:    Optional argv tail (e.g. ["--input-id", input_id]).
      witness_bytes: HTML/JSON bytes piped to the binary on stdin.
      input_id:      Cross-impl identity key for the diff engine.

    Returns:
      A dict matching schema/fact-vector-opengraph.schema.json.
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
    for axis in _REQUIRED_AXES:
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
    """Return the canonical crash envelope for the opengraph fact-vector schema.

    A wrapper that cannot produce a real parse (binary absent, crash,
    malformed JSON) emits this shape. The diff engine treats `crash` as a
    first-class disagreement axis value — a one-crash-one-ok divergence
    routes to HIGH triage automatically.
    """
    envelope: dict[str, Any] = {
        "input_id": input_id,
        "parser_profile": profile,
        "schema_version": "v1.0",
        "binary_missing": bool(binary_missing),
        "errors": [reason],
        "decode_outcome": {"status": status, "bytes_out": 0},
        "parser_warnings": ["wrapper crash recorded as a Finding"],
    }
    for axis in _REQUIRED_AXES:
        envelope[axis] = None
    return envelope


__all__ = ["dispatch", "_crash_envelope", "SUBPROCESS_TIMEOUT_S"]
