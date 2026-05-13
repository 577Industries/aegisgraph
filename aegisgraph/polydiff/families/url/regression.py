"""URL family regression run.

Loads the on-disk regression corpus (`polydiff/regression/build_corpus.py`
+ `polydiff/regression/cases/<id>/input` overrides), dispatches the
available URL parser wrappers via `profiles.fact_vectors_for`, computes
disagreements + Finding records, and emits the report.

Extracted from the monolithic `aegisgraph/polydiff.py` as part of
T-M2.3 (PolyDiff URL family refactor). Pure refactor — no behavior
change.

The `run_regression` entrypoint accepts injectable `write_json` /
`fact_vectors_for` / `detect_disagreements` arguments so the
`aegisgraph.polydiff` facade can re-bind them at the facade module
level (preserving the historical monkeypatch contract: tests do
`monkeypatch.setattr(aegisgraph.polydiff, "write_json", fake)` and
expect the patch to flow through the run).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable, Iterable

from aegisgraph.constants import STATIC_GENERATED_AT
from aegisgraph.evidence import evidence_ref, finalize_record, provenance
from aegisgraph.io import sha256_text
from aegisgraph.score import link_parser_score

from ...core.triage import Disagreement
from .profiles import _wrapper_command, _source_root, load_parser_status


def _load_cases(root: Path) -> Iterable[tuple[str, str, dict[str, Any], str | None, list[str]]]:
    """Yield (case_id, raw_url, expected_dict, historical_cve, primary_tags) tuples."""
    # Source of truth: build_corpus.CASES (Python module).
    # Try `root` first; fall back to source repo so tmp-dir test runs work.
    CASES: list = []
    for candidate in (root, _source_root()):
        sys.path.insert(0, str(candidate))
        try:
            from polydiff.regression.build_corpus import CASES as _C  # type: ignore[import-not-found]
            CASES = list(_C)
            break
        except Exception:
            continue
        finally:
            if str(candidate) in sys.path:
                sys.path.remove(str(candidate))

    for c in CASES:
        # If an on-disk case dir exists, prefer its `input` so the operator
        # can hand-edit a case without round-tripping the Python file.
        case_dir = root / "polydiff" / "regression" / "cases" / c.case_id
        input_path = case_dir / "input"
        url = input_path.read_text(encoding="utf-8") if input_path.exists() else c.input_url
        yield c.case_id, url, {
            "primary_axes": c.primary_axes,
            "primary_security_tags": c.primary_security_tags,
            "expected_disagreements": c.expected_pairs,
            "historical_cve_or_disclosure_reference": c.historical_cve_or_disclosure_reference,
            "publication_policy": c.publication_policy,
            "summary": c.summary,
            "bug_class": c.bug_class,
            "reference_url": c.reference_url,
        }, c.historical_cve_or_disclosure_reference, c.primary_security_tags


def _matches_expected(disagreements: list[Disagreement], expected: dict[str, Any]) -> bool:
    """A case is `rediscovered` iff every expected primary axis surfaces in the disagreement set
    AND every expected security tag is attached to at least one disagreement.

    For baseline cases (empty primary_axes), always returns True.
    """
    if not expected.get("primary_axes"):
        return True

    axes_seen = {d.axis for d in disagreements}
    if not all(a in axes_seen for a in expected["primary_axes"]):
        return False

    tags_seen: set[str] = set()
    for d in disagreements:
        tags_seen.update(d.security_tags)
    if not all(t in tags_seen for t in expected.get("primary_security_tags", [])):
        return False
    return True


def _normalize_record_id(case_id: str) -> str:
    """Map a case_id (mixed-case-with-dashes) to the schema-required
    `^AG-EV-[A-Z0-9-]+$` format. Underscores become dashes; runs of
    non-alphanumeric become a single dash.
    """
    out = []
    for ch in case_id.upper():
        if ch.isalnum() or ch == "-":
            out.append(ch)
        else:
            out.append("-")
    # Collapse repeated dashes.
    s = "".join(out)
    while "--" in s:
        s = s.replace("--", "-")
    return s.strip("-")


def _finding_record(
    index: int,
    case_id: str,
    raw_url: str,
    expected: dict[str, Any],
    disagreements: list[Disagreement],
    parser_profiles_used: list[str],
    previous_hash: str | None,
) -> dict[str, Any]:
    axes = ", ".join(sorted({d.axis for d in disagreements})) or "<none>"
    historical = expected.get("historical_cve_or_disclosure_reference")
    record = {
        "id": f"AG-EV-POLYDIFF-{_normalize_record_id(case_id)}",
        "version": "v1.0",
        "target": {
            "name": "PolyDiff URL parser regression corpus (>=30 historical cases)",
            "repo_url": "local://polydiff/regression",
            "commit": "stream/polydiff-core",
            "source_policy": "synthetic",
        },
        "path_class": "link_preview",
        "nodes": [
            {
                "id": f"entry.case-{case_id}",
                "node_type": "entry_point",
                "label": expected.get("bug_class", "url-parser-disagreement"),
                "source_anchor": f"polydiff/regression/cases/{case_id}",
                "evidence_source": expected.get("reference_url", "polydiff regression corpus"),
            },
            {
                "id": "parser.fact-vector",
                "node_type": "fact_vector",
                "label": f"Disagreement axes: {axes}",
                "source_anchor": "polydiff/factvec/schema_v2.json",
                "evidence_source": "PolyDiff v2 differential parser dispatch",
            },
        ],
        "edges": [
            {"from": f"entry.case-{case_id}", "to": "parser.fact-vector", "relationship": "parsed_by_profiles"},
        ],
        "score_vector": link_parser_score(),
        "claim_state": "reviewed",
        "validation_task": {
            "id": f"VAL-POLYDIFF-{_normalize_record_id(case_id)}",
            "command": "make polydiff-regression",
            "expected_output": "deterministic disagreement record matching expected.json",
            "status": "passing",
        },
        "evidence_refs": [
            evidence_ref(
                f"REF-POLYDIFF-{_normalize_record_id(case_id)}",
                "aegisgraph-polydiff",
                "make polydiff-regression",
                f"{case_id}:{sha256_text(raw_url)}",
            )
        ],
        "recommendation_refs": [],
        "limitations": (
            "PolyDiff regression case derived from public bug-class literature. "
            "Inputs use IETF-reserved example domains (RFC 2606) and reserved IPv4 "
            "ranges (RFC 5737/5736). This record is bounded parser-behavior evidence; "
            "it is not a claim of a live vulnerability in any maintained library or "
            "service."
            + (f" Historical reference: {historical}." if historical else "")
        ),
        "provenance": provenance(f"PolyDiff regression case {case_id}; parsers: {','.join(sorted(parser_profiles_used))}"),
        "safety_flags": [],
    }
    return finalize_record(record, previous_hash=previous_hash)


def run_regression(
    root: Path,
    *,
    write_json: Callable[[Path, dict[str, Any]], Path],
    fact_vectors_for: Callable[..., list[dict[str, Any]]],
    detect_disagreements: Callable[[list[dict[str, Any]]], list[Disagreement]],
) -> dict[str, Any]:
    """End-to-end URL-family regression run.

    Discovers available URL parser wrappers, runs them against the
    corpus, builds disagreements + findings, emits report + evidence.

    `write_json`, `fact_vectors_for`, and `detect_disagreements` are
    injected by the facade (`aegisgraph.polydiff.__init__`) so its
    module-level bindings are honored when tests monkeypatch them.
    """
    status = load_parser_status(root)
    available_profiles: list[str] = []
    skipped_profiles: list[dict[str, str]] = []
    for profile, entry in sorted(status.items()):
        if _wrapper_command(profile, entry, root) is not None:
            available_profiles.append(profile)
        else:
            skipped_profiles.append({
                "parser_profile": profile,
                "status": entry.get("status", "unknown"),
                "reason": entry.get("reason", ""),
                "directory": entry.get("directory", ""),
            })

    all_vectors: list[dict[str, Any]] = []
    all_disagreements: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    rediscoveries: list[dict[str, Any]] = []
    rediscovered_historical_cves = 0
    parser_failures: list[dict[str, str]] = []
    previous_hash: str | None = None

    cases_index: list[dict[str, Any]] = []

    for index, (case_id, raw_url, expected, historical, primary_tags) in enumerate(_load_cases(root), start=1):
        vectors = fact_vectors_for(case_id, raw_url, root=root)
        all_vectors.extend(vectors)
        for v in vectors:
            if v.get("errors") and v.get("parsed") is False and "wrapper" in (v.get("parse_error") or ""):
                parser_failures.append({
                    "case_id": case_id,
                    "parser_profile": v.get("parser_profile", "?"),
                    "reason": v.get("parse_error", ""),
                })

        disagreements = detect_disagreements(vectors)
        all_disagreements.extend(d.to_dict() for d in disagreements)

        matched = _matches_expected(disagreements, expected)
        rediscoveries.append({
            "case_id": case_id,
            "matched": matched,
            "primary_axes_expected": list(expected.get("primary_axes", [])),
            "primary_security_tags_expected": list(expected.get("primary_security_tags", [])),
            "axes_observed": sorted({d.axis for d in disagreements}),
            "tags_observed": sorted({t for d in disagreements for t in d.security_tags}),
            "historical_cve_or_disclosure_reference": historical,
        })

        if matched and historical:
            rediscovered_historical_cves += 1

        if disagreements:
            record = _finding_record(
                index, case_id, raw_url, expected, disagreements,
                parser_profiles_used=available_profiles,
                previous_hash=previous_hash,
            )
            previous_hash = record["hash_chain"]["record_hash"]
            records.append(record)

        cases_index.append({
            "case_id": case_id,
            "summary": expected.get("summary", ""),
            "historical_cve_or_disclosure_reference": historical,
            "disagreements": len(disagreements),
            "matched": matched,
        })

    historical_cve_total = sum(1 for r in rediscoveries if r["historical_cve_or_disclosure_reference"])

    report = {
        "tool_output_type": "polydiff_regression_report",
        "version": "v2.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "parser_profiles": available_profiles,
        "skipped_parsers": skipped_profiles,
        "parser_failures": parser_failures,
        "fact_vector_schema": "polydiff/factvec/schema_v2.json",
        "inputs_checked": len(cases_index),
        "fact_vectors": all_vectors,
        "disagreements": all_disagreements,
        "records": records,
        "rediscoveries": rediscoveries,
        "rediscovered_historical_cves": rediscovered_historical_cves,
        "historical_cve_cases_total": historical_cve_total,
        "tier_p1_status": "pass" if rediscovered_historical_cves >= 3 else "fail",
        "cases_index": cases_index,
    }
    write_json(root / "polydiff" / "regression" / "report.json", report)
    write_json(root / "polydiff" / "evidence" / "regression.evidence.json", {"records": records})
    return report


__all__ = [
    "run_regression",
    "_load_cases",
    "_matches_expected",
    "_normalize_record_id",
    "_finding_record",
]
