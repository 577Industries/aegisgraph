"""Regression: emitted AG-CRASH-* records must NEVER carry raw crash bytes.

This is the *adversarial* version of test_crash_record_emission_validates_schema.
Schema validation alone isn't enough — additionalProperties:false would catch
a top-level `bytes_b64` field, but a subtle bug could stash the bytes inside
`provenance.notes` or `asan_summary` or some new field. We walk the entire
record tree and assert that no leaf value contains base64-shaped data of
non-trivial length, no field named in our deny-list exists, and the only
crash-bytes signal is the SHA-256 in `crash_sha256`.

Per ADR-0013 / sanitize-check Rule 5: this is the bytes-on-disk gate; if
this test fails, the crash record builder has a contract violation.
"""

from __future__ import annotations

import re
from typing import Any

from aegisgraph.harnessgen.harnessgen import build_crash_record


FORBIDDEN_KEYS = frozenset(
    {
        "bytes_b64",
        "payload",
        "raw_bytes",
        "raw_witness",
        "crash_input",
        "crash_bytes",
        "witness_bytes",
        "minimized_input",
        "minimized_bytes",
        "payload_b64",
    }
)

# Any base64-shaped string ≥40 chars is treated as suspect. We exclude
# strict lowercase-hex strings (SHA-256 hex is 64 chars of [a-f0-9]) so
# the legitimate hash fields don't false-positive. Any string mixing
# uppercase, +, /, or = is treated as suspicious.
BASE64_BLOB_RE = re.compile(r"^(?=[A-Za-z0-9+/]{40,}={0,2}$)(?=.*[A-Z+/=]).*$")

# Field paths that are EXPECTED to carry SHA-256 hashes (lowercase hex).
# These are not base64 blobs even though the regex would match a 64-char
# `[a-f0-9]` string under a permissive interpretation.
EXPECTED_HASH_FIELDS = frozenset(
    {
        "crash_sha256",
        "stack_trace_hash",
        "hash_chain.record_hash",
        "hash_chain.previous_hash",
    }
)


def _walk(obj: Any, path: str = "") -> list[tuple[str, Any]]:
    """Yield (jsonpath, value) for every leaf in the record."""
    out: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_walk(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_walk(v, f"{path}[{i}]"))
    else:
        out.append((path, obj))
    return out


def _sample_crash() -> dict:
    return build_crash_record(
        harness_id="WebPDecodeRGB",
        crash_bytes=b"\x52\x49\x46\x46WEBPVP8\x00" + b"\xff" * 80,
        stack_trace_text=(
            "==12345==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 BuildHuffmanTable\n"
        ),
        crash_class="heap-buffer-overflow",
        discovery_engine="harnessgen",
        path_id="libwebp/decode",
    )


def _walk_keys(obj: Any) -> list[str]:
    """Yield every dict key in the record tree."""
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.append(k)
            keys.extend(_walk_keys(v))
    elif isinstance(obj, list):
        for v in obj:
            keys.extend(_walk_keys(v))
    return keys


def test_no_forbidden_key_names() -> None:
    record = _sample_crash()
    keys = set(_walk_keys(record))
    leaked = keys & FORBIDDEN_KEYS
    assert not leaked, f"crash record leaks forbidden keys: {leaked}"


def test_no_base64_blobs_in_record() -> None:
    """No string leaf value matches base64 of non-trivial length, except
    the well-known hash fields (which are hex, not base64)."""
    record = _sample_crash()
    for path, value in _walk(record):
        if path in EXPECTED_HASH_FIELDS:
            continue
        if isinstance(value, str) and BASE64_BLOB_RE.match(value):
            raise AssertionError(
                f"base64-shaped blob found at {path}: {value[:32]}..."
            )


def test_hash_fields_are_hex_not_base64() -> None:
    record = _sample_crash()
    # SHA-256 hex is exactly 64 chars of [a-f0-9].
    assert re.match(r"^[a-f0-9]{64}$", record["crash_sha256"])
    assert re.match(r"^[a-f0-9]{64}$", record["stack_trace_hash"])


def test_no_stack_trace_full_text_in_record() -> None:
    """The raw stack-trace text is hashed-not-stored. The frame
    identifiers (BuildHuffmanTable, etc.) MUST NOT appear in the
    serialized record."""
    record = _sample_crash()
    forbidden_substrings = (
        "BuildHuffmanTable",
        "VP8L",
        "==12345==",
        "ERROR:",
    )
    for path, value in _walk(record):
        if isinstance(value, str):
            for sub in forbidden_substrings:
                assert sub not in value, (
                    f"stack-trace leak: {sub!r} appears at {path}"
                )


def test_input_size_is_integer_not_bytes() -> None:
    record = _sample_crash()
    size = record["minimized_input_size_bytes"]
    assert isinstance(size, int)
    # The original payload was 12 + 80 = 92 bytes.
    assert size == 92


def test_safety_scan_has_no_blocking_flags() -> None:
    """Defense-in-depth: scan the record through aegisgraph.safety —
    the same gate the disclosure pipeline uses. Any blocking flag here
    means the record could leak bytes via a string match."""
    from aegisgraph.safety import blocking_flags, scan_record

    record = _sample_crash()
    flags = scan_record(record)
    blocks = blocking_flags(flags)
    assert not blocks, f"crash record tripped blocking flags: {[f.rule for f in blocks]}"
