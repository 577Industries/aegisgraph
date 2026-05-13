"""Round-trip integration: SARIF result -> AG-IV-* record validates against
`schema/invariant-violation.schema.json`.

This is the contract test that ties the SARIF consolidator output to the
M1 invariant-violation schema. If you break either side (consolidator or
schema), this test fails.

We also verify:

  * `aegisgraph.evidence.finalize_record`-style provenance + hash_chain
    are present on the consolidator's output.
  * `aegisgraph.safety.scan_record` finds no blocking flags on a
    synthetic record (no live-target language, no raw-bytes).
  * The hash chain verifies (round-trip).
"""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator

from aegisgraph.hashchain import verify_hash_chain
from aegisgraph.io import load_json, repo_root
from aegisgraph.safety import blocking_flags, scan_record
from aegisgraph.invariants.runner.sarif_consolidator import consolidate_sarif


def _stub_sarif() -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {"id": "aegisgraph/inv-01-url-fetch-without-policy"}
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "aegisgraph/inv-01-url-fetch-without-policy",
                        "level": "warning",
                        "message": {
                            "text": (
                                "URL parameter reaches HTTP fetch without "
                                "passing through a policy barrier."
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "app/src/main/java/Demo/Foo.java"
                                    },
                                    "region": {"startLine": 17, "startColumn": 9},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def _make_record() -> dict[str, Any]:
    records = consolidate_sarif(
        sarif=_stub_sarif(),
        target={
            "target_id": "demo-vulnerable-app",
            "repo_url": "https://github.com/example/demo-vulnerable-app",
            "commit": "abc1234",
        },
        rule_to_invariant={
            "aegisgraph/inv-01-url-fetch-without-policy": "INV-01"
        },
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    assert len(records) == 1
    return records[0]


def test_record_validates_against_invariant_violation_schema() -> None:
    schema = load_json(
        repo_root() / "schema" / "invariant-violation.schema.json"
    )
    # The schema $refs hash-chain.schema.json. Load it via a $ref resolver so
    # the test can find it in the same dir as the parent schema.
    record = _make_record()
    validator = Draft202012Validator(
        schema, registry=_make_registry()
    )
    errors = sorted(validator.iter_errors(record), key=str)
    error_msgs = [
        f"{'/'.join(str(part) for part in e.path)}: {e.message}" for e in errors
    ]
    assert not errors, (
        f"AG-IV-* record failed invariant-violation.schema.json validation:\n"
        + "\n".join(error_msgs)
    )


def _make_registry():
    """Build a jsonschema Registry that resolves hash-chain.schema.json
    relative-ref to the file on disk."""
    from referencing import Registry, Resource  # type: ignore[import-not-found]

    schema_dir = repo_root() / "schema"
    invariant_schema = load_json(schema_dir / "invariant-violation.schema.json")
    hash_chain_schema = load_json(schema_dir / "hash-chain.schema.json")
    return Registry().with_resources(
        [
            (
                invariant_schema["$id"],
                Resource.from_contents(invariant_schema),
            ),
            ("hash-chain.schema.json", Resource.from_contents(hash_chain_schema)),
            (
                hash_chain_schema["$id"],
                Resource.from_contents(hash_chain_schema),
            ),
        ]
    )


def test_record_carries_provenance_block() -> None:
    record = _make_record()
    prov = record["provenance"]
    assert prov["generated_by"], "provenance.generated_by must be non-empty"
    assert prov["generated_at"], "provenance.generated_at must be non-empty"
    assert prov["source"], "provenance.source must be non-empty"
    assert prov["private_by_default"] is True, (
        "AG-IV-* records ship private_by_default=True per safety posture"
    )


def test_record_hash_chain_verifies() -> None:
    record = _make_record()
    errors = verify_hash_chain(record)
    assert errors == [], f"hash chain failed: {errors}"


def test_record_has_no_blocking_safety_flags() -> None:
    record = _make_record()
    flags = scan_record(record)
    blocks = blocking_flags(flags)
    assert not blocks, (
        f"AG-IV-* record carries blocking safety flags: "
        f"{[f.rule for f in blocks]}"
    )


def test_record_violation_id_pattern() -> None:
    import re

    record = _make_record()
    assert re.match(r"^AG-IV-[A-Z0-9-]+$", record["violation_id"]), (
        f"violation_id {record['violation_id']!r} does not match pattern"
    )


def test_record_invariant_id_is_inv_01() -> None:
    record = _make_record()
    assert record["invariant_id"] == "INV-01"
    assert record["target_id"] == "demo-vulnerable-app"
    assert record["location"]["start_line"] == 17
