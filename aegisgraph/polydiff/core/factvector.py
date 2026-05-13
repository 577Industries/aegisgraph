"""Generic fact-vector dispatch primitives.

Hosts the family-agnostic wrapper-subprocess runner and the synthetic
crash-envelope helper. Family-specific dispatch (which wrappers to
run, where to find them, how to discover the corpus) lives under
`aegisgraph/polydiff/families/<family>/`.

Extracted from the monolithic `aegisgraph/polydiff.py` as part of
T-M2.3 (PolyDiff URL family refactor). Pure refactor — no behavior
change.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


SUBPROCESS_TIMEOUT_S = 5.0  # generous for cold-start; per-input budget is 100ms


def run_wrapper(profile: str, command: list[str], input_id: str, raw_url: str) -> dict[str, Any]:
    """Run a wrapper subprocess. Returns the v2 fact-vector envelope.

    On wrapper crash (non-zero exit, non-JSON stdout, timeout), returns
    a synthetic envelope with parsed=false and an error string. The
    crash itself is recorded in the report under `parser_failures`.
    """
    full_cmd = command + ["--input-id", input_id]
    try:
        proc = subprocess.run(
            full_cmd,
            input=raw_url.encode("utf-8"),
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _crash_envelope(profile, input_id, "wrapper subprocess timeout")
    except FileNotFoundError as exc:
        return _crash_envelope(profile, input_id, f"wrapper not found: {exc}")

    if proc.returncode != 0:
        return _crash_envelope(profile, input_id, f"wrapper exit code {proc.returncode}: {proc.stderr.decode('utf-8', 'replace')[:200]}")

    line = proc.stdout.decode("utf-8", "replace").strip()
    if not line:
        return _crash_envelope(profile, input_id, "wrapper produced no stdout")
    try:
        return json.loads(line.splitlines()[0])
    except json.JSONDecodeError as exc:
        return _crash_envelope(profile, input_id, f"wrapper produced invalid JSON: {exc}")


def _crash_envelope(profile: str, input_id: str, reason: str) -> dict[str, Any]:
    return {
        "schema_version": "v2",
        "input_id": input_id,
        "parser_profile": profile,
        "parsed": False,
        "errors": [reason],
        "warnings": ["wrapper crash recorded as a Finding"],
        "scheme": None,
        "host": None,
        "port": None,
        "path": None,
        "userinfo_present": False,
        "host_is_private_or_link_local": False,
        "parse_error": reason,
    }


__all__ = ["run_wrapper", "_crash_envelope", "SUBPROCESS_TIMEOUT_S"]
