"""Tests that the SARIF -> AG-IV-* consolidator produces well-formed records.

These tests use synthetic SARIF input (no live target probing, no live
CodeQL / Semgrep invocation), so they run anywhere — no codeql or
semgrep binaries required.

What we test here (contract):

  * `consolidate_sarif(sarif, ...)` returns a list of AG-IV-* record dicts.
  * Each record has the schema-required fields per
    `schema/invariant-violation.schema.json`: violation_id, version,
    discovery_engine, invariant_id, target_id, rule_id, severity,
    location (with repo_url, commit, path, start_line), sarif_result_uri,
    provenance, hash_chain.
  * `violation_id` matches `^AG-IV-[A-Z0-9-]+$`.
  * `version == "v1.0"` and `discovery_engine == "invariantcheck"`.
  * `invariant_id` is propagated from the caller's mapping.
  * Missing `start_line` defaults to 1 (or the consolidator skips the
    result with a documented reason — we test the chosen behavior).
  * Multiple SARIF results in a single run produce multiple AG-IV-* records.
  * Empty SARIF -> empty list (no crashes).

The full schema-validation round-trip lives in
`test_invariant_to_evidence_record.py`.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from aegisgraph.invariants.runner.sarif_consolidator import consolidate_sarif


VIOLATION_ID_RE = re.compile(r"^AG-IV-[A-Z0-9-]+$")


def _stub_sarif(results: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Minimal SARIF document with the structure CodeQL emits."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {"id": "aegisgraph/inv-01-url-fetch-without-policy"},
                            {"id": "aegisgraph/inv-11-deeplink-open-redirect"},
                        ],
                    }
                },
                "results": results or [],
            }
        ],
    }


def _stub_result(
    rule_id: str = "aegisgraph/inv-01-url-fetch-without-policy",
    uri: str = "src/main/java/example/Foo.java",
    start_line: int = 42,
    level: str = "warning",
    message: str = "Attacker-controlled URL reaches network fetch without policy barrier.",
) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": start_line},
                }
            }
        ],
    }


def _default_target() -> dict[str, str]:
    return {
        "target_id": "demo-vulnerable-app",
        "repo_url": "https://github.com/example/demo-vulnerable-app",
        "commit": "abc1234",
    }


def _default_rule_mapping() -> dict[str, str]:
    return {
        "aegisgraph/inv-01-url-fetch-without-policy": "INV-01",
        "aegisgraph/inv-11-deeplink-open-redirect": "INV-11",
    }


def test_empty_sarif_produces_empty_record_list() -> None:
    records = consolidate_sarif(
        sarif=_stub_sarif(),
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    assert records == []


def test_single_result_produces_single_record() -> None:
    sarif = _stub_sarif([_stub_result()])
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    assert len(records) == 1


def test_record_has_required_schema_fields() -> None:
    sarif = _stub_sarif([_stub_result()])
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    record = records[0]
    required = {
        "violation_id",
        "version",
        "discovery_engine",
        "invariant_id",
        "target_id",
        "rule_id",
        "severity",
        "location",
        "sarif_result_uri",
        "provenance",
        "hash_chain",
    }
    missing = required - set(record.keys())
    assert not missing, f"record missing required fields: {missing}"


def test_violation_id_pattern() -> None:
    sarif = _stub_sarif([_stub_result()])
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    assert VIOLATION_ID_RE.match(records[0]["violation_id"]), (
        f"violation_id {records[0]['violation_id']!r} does not match "
        f"^AG-IV-[A-Z0-9-]+$"
    )


def test_version_and_discovery_engine_constants() -> None:
    sarif = _stub_sarif([_stub_result()])
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    record = records[0]
    assert record["version"] == "v1.0"
    assert record["discovery_engine"] == "invariantcheck"


def test_invariant_id_propagated_from_mapping() -> None:
    sarif = _stub_sarif(
        [
            _stub_result(rule_id="aegisgraph/inv-01-url-fetch-without-policy"),
            _stub_result(rule_id="aegisgraph/inv-11-deeplink-open-redirect"),
        ]
    )
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    ids = [r["invariant_id"] for r in records]
    assert sorted(ids) == ["INV-01", "INV-11"]


def test_location_fields_populated() -> None:
    sarif = _stub_sarif(
        [_stub_result(uri="app/src/main/Foo.java", start_line=7)]
    )
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    location = records[0]["location"]
    assert location["repo_url"] == "https://github.com/example/demo-vulnerable-app"
    assert location["commit"] == "abc1234"
    assert location["path"] == "app/src/main/Foo.java"
    assert location["start_line"] == 7


def test_unmapped_rule_ids_are_skipped() -> None:
    """If a SARIF result references a rule_id not in our rule_to_invariant
    mapping, the consolidator skips it (it isn't one of *our* invariants).
    This is the design choice from extraction/adapters/codeql_to_graph.py.
    """
    sarif = _stub_sarif([_stub_result(rule_id="some-other-rule-not-ours")])
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    assert records == []


def test_severity_propagated_from_sarif_level() -> None:
    sarif = _stub_sarif([_stub_result(level="error")])
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    assert records[0]["severity"] == "error"


def test_default_severity_when_level_missing() -> None:
    """SARIF allows omitting `level`; SARIF 2.1.0 defaults to "warning"."""
    result = _stub_result()
    result.pop("level", None)
    sarif = _stub_sarif([result])
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    assert records[0]["severity"] == "warning"


def test_rule_engine_recorded() -> None:
    sarif = _stub_sarif([_stub_result()])
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/semgrep/sarif/run-007.sarif",
        rule_engine="semgrep",
    )
    assert records[0]["rule_engine"] == "semgrep"


def test_multiple_results_produce_distinct_violation_ids() -> None:
    sarif = _stub_sarif(
        [
            _stub_result(uri="a.java", start_line=10),
            _stub_result(uri="b.java", start_line=20),
            _stub_result(uri="c.java", start_line=30),
        ]
    )
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    ids = {r["violation_id"] for r in records}
    assert len(ids) == 3, f"expected 3 distinct violation_ids, got {ids}"


def test_consolidate_handles_missing_runs_block_gracefully() -> None:
    bad_sarif: dict[str, Any] = {"version": "2.1.0"}  # no "runs" key
    records = consolidate_sarif(
        sarif=bad_sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    assert records == []


def test_consolidate_handles_result_with_no_locations() -> None:
    """A SARIF result without `locations` cannot be anchored; the
    consolidator must skip it rather than emit a record missing the
    required `location.path` field."""
    result = _stub_result()
    result["locations"] = []
    sarif = _stub_sarif([result])
    records = consolidate_sarif(
        sarif=sarif,
        target=_default_target(),
        rule_to_invariant=_default_rule_mapping(),
        sarif_result_uri="engineering/codeql/sarif/run-001.sarif",
        rule_engine="codeql",
    )
    assert records == []
