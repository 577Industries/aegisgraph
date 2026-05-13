"""Deeplink-family wrapper modules.

Each module exposes:

    run(witness_bytes: bytes, input_id: str) -> dict[str, Any]

Returns a dict matching schema/fact-vector-deeplink.schema.json.
On any failure (binary missing, non-zero exit, malformed JSON output) the
wrapper returns a degenerate fact-vector with
decode_outcome.status=parse_error + binary_missing=True (where
applicable) rather than raising. This keeps the diff engine output
deterministic across environments.

Subprocess invocation is centralized in `_dispatch.py`; per-wrapper modules
declare the binary name + argv shape and call into the shared dispatcher.
This makes mocking trivial (patch subprocess.run once and every wrapper
sees the mocked output).

Note: deeplink wrappers MUST NOT fetch URLs over the network. They parse
the URI bytes from stdin only — no outbound HTTP requests permitted.
"""
