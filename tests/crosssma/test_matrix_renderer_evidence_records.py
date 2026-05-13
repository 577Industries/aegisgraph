"""matrix renderer evidence record contract test.

Every AG-XSMA-* record produced by matrix_renderer.render_matrix MUST
validate against schema/cross-target-candidate.schema.json. The hash
chain must verify. No blocking safety flags.
"""

from __future__ import annotations

import re

from aegisgraph.crosssma.matrix_renderer import (
    GraphThread,
    render_matrix,
)
from aegisgraph.crosssma.pattern_extractor import PatternFingerprint
from aegisgraph.crosssma.target_registry import load_registry
from aegisgraph.hashchain import verify_hash_chain
from aegisgraph.io import load_json, repo_root
from aegisgraph.safety import blocking_flags, scan_record


def _single_thread() -> GraphThread:
    return GraphThread(
        thread_id="SIG-GP-001",
        source_target_id="signal-android",
        title="Remote URL in composer to link preview metadata and thumbnail fetch",
        path_class="link_preview",
        pattern_type="parser_disagreement",
        family="url",
        axis="backslash_handling",
        implementations=("java.net.URI", "whatwg-url"),
        dependency_keys=("libwebp",),
    )


def _make_one_record() -> dict:
    thread = _single_thread()
    registry = load_registry()
    records = render_matrix([thread], registry)
    assert len(records) == 1
    return records[0]


def test_record_validates_against_cross_target_candidate_schema() -> None:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    schema_dir = repo_root() / "schema"
    cross_schema = load_json(schema_dir / "cross-target-candidate.schema.json")
    hash_chain_schema = load_json(schema_dir / "hash-chain.schema.json")

    registry_ref = Registry().with_resources(
        [
            (cross_schema["$id"], Resource.from_contents(cross_schema)),
            ("hash-chain.schema.json", Resource.from_contents(hash_chain_schema)),
            (hash_chain_schema["$id"], Resource.from_contents(hash_chain_schema)),
        ]
    )
    record = _make_one_record()
    validator = Draft202012Validator(cross_schema, registry=registry_ref)
    errors = sorted(validator.iter_errors(record), key=str)
    error_msgs = [
        f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in errors
    ]
    assert not errors, (
        "AG-XSMA-* record failed cross-target-candidate.schema.json validation:\n"
        + "\n".join(error_msgs)
    )


def test_record_candidate_id_pattern() -> None:
    record = _make_one_record()
    assert re.fullmatch(
        r"AG-XSMA-[A-Z0-9-]+", record["candidate_id"]
    ), f"candidate_id {record['candidate_id']!r} does not match pattern"


def test_record_hash_chain_verifies() -> None:
    record = _make_one_record()
    errors = verify_hash_chain(record)
    assert errors == [], f"hash chain failed: {errors}"


def test_record_version_and_engine() -> None:
    record = _make_one_record()
    assert record["version"] == "v1.0"
    assert record["discovery_engine"] == "crosssma"


def test_record_no_blocking_safety_flags() -> None:
    record = _make_one_record()
    flags = scan_record(record)
    blocks = blocking_flags(flags)
    assert not blocks, (
        f"AG-XSMA-* record carries blocking safety flags: "
        f"{[f.rule for f in blocks]}"
    )


def test_record_target_findings_includes_all_four_targets() -> None:
    record = _make_one_record()
    target_ids = sorted(c["target"] for c in record["target_findings"])
    assert target_ids == sorted(
        [
            "signal-android",
            "element-x-android",
            "wire-android",
            "telegram-android",
        ]
    )


def test_record_source_target_cell_confirmed_reachable() -> None:
    """The target where the finding originated must be marked
    confirmed_reachable in its own cell."""
    record = _make_one_record()
    source_cells = [
        c for c in record["target_findings"] if c["target"] == "signal-android"
    ]
    assert len(source_cells) == 1
    assert source_cells[0]["status"] == "confirmed_reachable"


def test_record_structural_signature_is_hex_sha256() -> None:
    record = _make_one_record()
    assert re.fullmatch(r"[a-f0-9]{64}", record["structural_signature"])


def test_record_provenance_block_present() -> None:
    record = _make_one_record()
    prov = record["provenance"]
    assert prov["generated_by"]
    assert prov["generated_at"]
    assert prov["source"]
    assert prov["private_by_default"] is True
