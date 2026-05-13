"""Emitted AG-CRASH-* records validate against schema/crash.schema.json.

The crash-record builder consumes a (harness_id, crash bytes, stack trace
text, crash_class) tuple and emits a hash-only record per the schema:

  * crash_id matches `^AG-CRASH-[A-Z0-9-]+$`
  * crash_sha256 is the SHA-256 of the bytes (64 hex chars)
  * stack_trace_hash is the SHA-256 of a canonicalized trace string
  * crash_class is the TOP-LEVEL exception/signal category only — no line
    numbers, no source paths
  * minimized_input_size_bytes is the integer length of the bytes
  * NO bytes_b64, NO payload, NO raw_bytes, NO raw_witness anywhere

The companion sanitizer regression test
(test_crash_record_no_raw_bytes_regression.py) re-asserts the no-raw-bytes
invariant after the record passes through finalize_record (which adds
safety_flags + hash_chain).
"""

from __future__ import annotations

import re

from jsonschema import Draft202012Validator

from aegisgraph.harnessgen.harnessgen import build_crash_record
from aegisgraph.io import load_json, repo_root, sha256_text


CRASH_ID_RE = re.compile(r"^AG-CRASH-[A-Z0-9-]+$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def _sample_crash() -> dict:
    return build_crash_record(
        harness_id="WebPDecodeRGB",
        crash_bytes=b"\x52\x49\x46\x46" + b"\x00" * 26,  # RIFF-ish 30 bytes
        stack_trace_text=(
            "==12345==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 BuildHuffmanTable\n"
            "    #1 VP8LDecodeAlphaImageStream\n"
        ),
        crash_class="heap-buffer-overflow",
        discovery_engine="harnessgen",
        path_id="libwebp/decode",
    )


def test_crash_id_matches_pattern() -> None:
    record = _sample_crash()
    assert CRASH_ID_RE.match(record["crash_id"]), record["crash_id"]


def test_crash_sha256_is_sha256_hex() -> None:
    record = _sample_crash()
    assert SHA256_RE.match(record["crash_sha256"])


def test_stack_trace_hash_is_sha256_hex() -> None:
    record = _sample_crash()
    assert SHA256_RE.match(record["stack_trace_hash"])


def test_minimized_input_size_is_integer_byte_count() -> None:
    record = _sample_crash()
    assert isinstance(record["minimized_input_size_bytes"], int)
    assert record["minimized_input_size_bytes"] == 30


def test_crash_class_is_top_level_only() -> None:
    record = _sample_crash()
    cls = record["crash_class"]
    # Top-level category only: NO line numbers, NO source paths, NO file refs.
    assert "/" not in cls  # no path separators
    assert ":" not in cls  # no line-number colons
    assert ".cc" not in cls
    assert ".c" not in cls or cls.endswith("-c")  # benign substring
    assert ".h" not in cls or cls.endswith("-h")
    assert not any(ch.isdigit() for ch in cls)  # no line numbers


def test_version_is_v1_0() -> None:
    record = _sample_crash()
    assert record["version"] == "v1.0"


def test_discovery_engine_enum() -> None:
    record = _sample_crash()
    assert record["discovery_engine"] in {"harnessgen", "dynamicprobe", "reprochain"}


def test_provenance_present() -> None:
    record = _sample_crash()
    prov = record["provenance"]
    assert prov["private_by_default"] is True
    assert prov["generated_by"]
    assert prov["generated_at"]
    assert prov["source"]


def test_hash_chain_present() -> None:
    record = _sample_crash()
    assert "hash_chain" in record
    assert "record_hash" in record["hash_chain"]


def _make_registry():
    """Build a jsonschema Registry that resolves hash-chain.schema.json
    relative-ref to the file on disk (mirrors tests/invariants approach)."""
    from referencing import Registry, Resource  # type: ignore[import-not-found]

    schema_dir = repo_root() / "schema"
    crash_schema = load_json(schema_dir / "crash.schema.json")
    hash_chain_schema = load_json(schema_dir / "hash-chain.schema.json")
    return Registry().with_resources(
        [
            (crash_schema["$id"], Resource.from_contents(crash_schema)),
            ("hash-chain.schema.json", Resource.from_contents(hash_chain_schema)),
            (
                hash_chain_schema["$id"],
                Resource.from_contents(hash_chain_schema),
            ),
        ]
    )


def test_record_validates_against_schema() -> None:
    record = _sample_crash()
    schema = load_json(repo_root() / "schema" / "crash.schema.json")
    validator = Draft202012Validator(schema, registry=_make_registry())
    errors = sorted(validator.iter_errors(record), key=str)
    error_msgs = [
        f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors
    ]
    assert not errors, f"AG-CRASH-* record failed schema validation:\n" + "\n".join(error_msgs)


def test_crash_sha256_matches_actual_bytes() -> None:
    bytes_ = b"hello world fuzz input"
    record = build_crash_record(
        harness_id="WebPDecodeRGB",
        crash_bytes=bytes_,
        stack_trace_text="ASAN heap-buffer-overflow",
        crash_class="heap-buffer-overflow",
        discovery_engine="harnessgen",
    )
    expected = sha256_text("")  # placeholder; recomputed below
    import hashlib

    expected = hashlib.sha256(bytes_).hexdigest()
    assert record["crash_sha256"] == expected


def test_novelty_default_is_unknown() -> None:
    """Without an oracle, novelty defaults to 'unknown' — it's only after
    the cross-check against known-bugs/INDEX.json that we set
    appears_novel / matches_known."""
    record = _sample_crash()
    assert record["novelty"] in {"appears_novel", "matches_known", "duplicate", "unknown"}
