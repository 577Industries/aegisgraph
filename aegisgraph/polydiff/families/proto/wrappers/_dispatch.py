"""Shared subprocess dispatch for proto-family wrappers.

Each per-implementation wrapper (protoc_python, flatc_runner,
msgpack_python, protoc_gogofaster_stub) declares its binary name +
argv, its format_kind, and calls into `dispatch()`. The dispatcher:

  1. Invokes the binary with witness bytes on stdin.
  2. Parses one JSON line from stdout (per the wrapper subprocess
     contract).
  3. Returns the parsed dict on success.
  4. On FileNotFoundError, non-zero exit, timeout, or malformed JSON,
     returns a `_crash_envelope`-equivalent fact-vector with
     decode_outcome.status='parse_error' (and binary_missing=true when
     the binary itself is absent).

The envelope always validates against
schema/fact-vector-proto.schema.json.

Mirror of aegisgraph/polydiff/families/qr/wrappers/_dispatch.py with
the proto axes substituted. Note: the proto schema does NOT include
'crash' as a decode_outcome.status; the canonical absence / failure
signal is 'parse_error' paired with binary_missing=true.

The gogofaster stub calls `stub_envelope()` directly instead of
dispatching to a subprocess — the binary is known to be absent in
every devcontainer.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


SUBPROCESS_TIMEOUT_S = 10.0  # generous; cold-start of decoders can be slow

# Required axes from the proto fact-vector schema. The dispatch layer
# defaults any axis that the subprocess omitted so the resulting envelope
# always validates against the schema.
_REQUIRED_AXES_NULLABLE = (
    "declared_schema_version",
    "message_type_name",
    "field_count",
    "field_unknown_count",
    "oneof_active_field",
    "decoded_field_summary",
)


def dispatch(
    *,
    profile: str,
    binary: str,
    format_kind: str,
    extra_args: list[str] | None,
    witness_bytes: bytes,
    input_id: str,
) -> dict[str, Any]:
    """Run a proto-family wrapper subprocess. Always returns a fact-vector.

    Args:
      profile:       Wrapper id (protoc_python, flatc_runner,
                     msgpack_python, protoc_gogofaster_stub).
      binary:        Executable name as it must appear on PATH.
      format_kind:   One of {protobuf, flatbuffer, msgpack}; defaults the
                     `format_kind` axis if the subprocess omits it.
      extra_args:    Optional argv tail (e.g. ["--input-id", input_id]).
      witness_bytes: Binary payload bytes piped to the binary on stdin.
      input_id:      Cross-impl identity key for the diff engine.

    Returns:
      A dict matching schema/fact-vector-proto.schema.json.
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
            format_kind=format_kind,
            reason=f"wrapper binary missing: {binary}",
            binary_missing=True,
        )
    except subprocess.TimeoutExpired:
        return _crash_envelope(
            profile=profile,
            input_id=input_id,
            format_kind=format_kind,
            reason="wrapper subprocess timeout",
            binary_missing=False,
        )

    if proc.returncode != 0:
        return _crash_envelope(
            profile=profile,
            input_id=input_id,
            format_kind=format_kind,
            reason=(
                f"wrapper exit code {proc.returncode}: "
                + proc.stderr.decode("utf-8", "replace")[:200]
            ),
            binary_missing=False,
            status="parse_error",
        )

    line = proc.stdout.decode("utf-8", "replace").strip()
    if not line:
        return _crash_envelope(
            profile=profile,
            input_id=input_id,
            format_kind=format_kind,
            reason="wrapper produced no stdout",
            binary_missing=False,
        )
    try:
        envelope = json.loads(line.splitlines()[0])
    except json.JSONDecodeError as exc:
        return _crash_envelope(
            profile=profile,
            input_id=input_id,
            format_kind=format_kind,
            reason=f"wrapper produced invalid JSON: {exc}",
            binary_missing=False,
        )

    # Ensure required identity keys are populated (the binary may omit them).
    envelope.setdefault("input_id", input_id)
    envelope.setdefault("parser_profile", profile)
    envelope.setdefault("format_kind", format_kind)
    # Ensure every required axis is present; the schema requires explicit
    # nulls rather than missing keys.
    for axis in _REQUIRED_AXES_NULLABLE:
        envelope.setdefault(axis, None)
    envelope.setdefault("decode_outcome", {"status": "ok", "bytes_out": 0})
    envelope.setdefault("parser_warnings", [])
    return envelope


def _crash_envelope(
    *,
    profile: str,
    input_id: str,
    format_kind: str,
    reason: str,
    binary_missing: bool,
    status: str = "parse_error",
) -> dict[str, Any]:
    """Return the canonical crash envelope for the proto fact-vector schema.

    A wrapper that cannot produce a real decode (binary absent, crash,
    malformed JSON) emits this shape. The diff engine treats
    'parse_error' as a first-class disagreement axis value — a
    one-ok-one-parse_error divergence routes to HIGH triage
    automatically.
    """
    envelope: dict[str, Any] = {
        "input_id": input_id,
        "parser_profile": profile,
        "schema_version": "v1.0",
        "binary_missing": bool(binary_missing),
        "errors": [reason],
        "format_kind": format_kind,
        "declared_schema_version": None,
        "message_type_name": None,
        "field_count": None,
        "field_unknown_count": None,
        "oneof_active_field": None,
        "decoded_field_summary": None,
        "decode_outcome": {"status": status, "bytes_out": 0},
        "parser_warnings": ["wrapper crash recorded as a Finding"],
    }
    return envelope


def stub_envelope(
    *,
    profile: str,
    input_id: str,
    format_kind: str,
    reason: str,
) -> dict[str, Any]:
    """Return a binary_missing envelope without invoking subprocess.run.

    Used by protoc_gogofaster_stub — the wrapper knows in advance that
    the underlying decoder is not available in the devcontainer.
    """
    return _crash_envelope(
        profile=profile,
        input_id=input_id,
        format_kind=format_kind,
        reason=reason,
        binary_missing=True,
    )


__all__ = ["dispatch", "stub_envelope", "_crash_envelope", "SUBPROCESS_TIMEOUT_S"]
