"""Shared subprocess dispatch for deeplink-family wrappers.

Each per-implementation wrapper (android_intent_uri, ios_universal_link,
web_url_fallback, custom_scheme_parser) declares its binary name + argv
and calls into `dispatch()`. The dispatcher:

  1. Invokes the binary with witness bytes on stdin.
  2. Parses one JSON line from stdout (per the wrapper subprocess
     contract).
  3. Returns the parsed dict on success.
  4. On FileNotFoundError, non-zero exit, timeout, or malformed JSON,
     returns a `_crash_envelope`-equivalent fact-vector with
     decode_outcome.status='parse_error' (and binary_missing=true when
     the binary itself is absent).

The envelope always validates against
schema/fact-vector-deeplink.schema.json.

Mirror of aegisgraph/polydiff/families/opengraph/wrappers/_dispatch.py
with the deeplink axes substituted. Note: the deeplink schema does NOT
include 'crash' as a decode_outcome.status; the canonical absence /
failure signal is 'parse_error' paired with binary_missing=true.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


SUBPROCESS_TIMEOUT_S = 10.0  # generous; cold-start of parsers can be slow

# Required axes from the deeplink fact-vector schema. The dispatch layer
# defaults any axis that the subprocess omitted so the resulting envelope
# always validates against the schema.
_REQUIRED_AXES_STRING_OR_NULL = (
    "host",
    "path",
    "fragment_action",
    "intent_action",
)
_REQUIRED_AXES_LIST_OR_NULL = (
    "intent_category",
)
_REQUIRED_AXES_OBJECT_OR_NULL = (
    "query_params",
)


def dispatch(
    *,
    profile: str,
    binary: str,
    extra_args: list[str] | None,
    witness_bytes: bytes,
    input_id: str,
) -> dict[str, Any]:
    """Run a deeplink-family wrapper subprocess. Always returns a fact-vector.

    Args:
      profile:       Wrapper id (android_intent_uri / ios_universal_link /
                     web_url_fallback / custom_scheme_parser).
      binary:        Executable name as it must appear on PATH.
      extra_args:    Optional argv tail (e.g. ["--input-id", input_id]).
      witness_bytes: URI bytes piped to the binary on stdin.
      input_id:      Cross-impl identity key for the diff engine.

    Returns:
      A dict matching schema/fact-vector-deeplink.schema.json.
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
            status="parse_error",
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
    # nulls / empty containers rather than missing keys.
    envelope.setdefault("scheme", "")
    for axis in _REQUIRED_AXES_STRING_OR_NULL:
        envelope.setdefault(axis, None)
    for axis in _REQUIRED_AXES_LIST_OR_NULL:
        envelope.setdefault(axis, None)
    for axis in _REQUIRED_AXES_OBJECT_OR_NULL:
        envelope.setdefault(axis, None)
    envelope.setdefault("declared_permissions", [])
    envelope.setdefault("decode_outcome", {"status": "ok", "bytes_out": 0})
    envelope.setdefault("parser_warnings", [])
    return envelope


def _crash_envelope(
    *,
    profile: str,
    input_id: str,
    reason: str,
    binary_missing: bool,
    status: str = "parse_error",
) -> dict[str, Any]:
    """Return the canonical crash envelope for the deeplink fact-vector schema.

    A wrapper that cannot produce a real parse (binary absent, crash,
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
        "scheme": "",
        "host": None,
        "path": None,
        "query_params": None,
        "fragment_action": None,
        "declared_permissions": [],
        "intent_action": None,
        "intent_category": None,
        "decode_outcome": {"status": status, "bytes_out": 0},
        "parser_warnings": ["wrapper crash recorded as a Finding"],
    }
    return envelope


__all__ = ["dispatch", "_crash_envelope", "SUBPROCESS_TIMEOUT_S"]
