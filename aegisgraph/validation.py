from __future__ import annotations

from pathlib import Path
from typing import Any

from .io import load_json, write_json
from .schema import check_schema_files, validate_against_schema, validate_evidence_record


def _records_from_document(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, dict) and document.get("version") == "v1.0" and str(document.get("id", "")).startswith("AG-EV-"):
        return [document]
    if isinstance(document, dict) and isinstance(document.get("records"), list):
        return [record for record in document["records"] if isinstance(record, dict)]
    if isinstance(document, dict) and isinstance(document.get("evidence_records"), list):
        return [record for record in document["evidence_records"] if isinstance(record, dict)]
    return []


def evidence_documents(root: Path) -> list[Path]:
    candidates: list[Path] = []
    patterns = [
        "extraction/output/**/*.json",
        "reprochain/evidence/**/*.json",
        "polydiff/evidence/**/*.json",
        "exports/private-submission/**/*.json",
        "exports/public-sanitized/**/*.json",
    ]
    for pattern in patterns:
        candidates.extend(root.glob(pattern))
    return sorted({path for path in candidates if path.is_file()})


def validate_repo(root: Path) -> dict[str, Any]:
    schema_errors = check_schema_files(root)
    record_results = []
    records_checked = 0
    for path in evidence_documents(root):
        try:
            document = load_json(path)
        except Exception as exc:
            record_results.append({"path": str(path.relative_to(root)), "errors": [f"could not parse JSON: {exc}"]})
            continue
        for record in _records_from_document(document):
            records_checked += 1
            record_results.append(
                {
                    "path": str(path.relative_to(root)),
                    "record_id": record.get("id"),
                    "errors": validate_evidence_record(record, root),
                }
            )

        if isinstance(document, dict) and "tool_output_type" in document:
            errors = validate_against_schema(document, "tool-output.schema.json", root)
            if errors:
                record_results.append({"path": str(path.relative_to(root)), "errors": errors})

    failures = [result for result in record_results if result.get("errors")]
    report = {
        "tool_output_type": "validation_report",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": "2026-05-05T00:00:00Z",
        "safety_posture": "private_by_default",
        "schemas_checked": len(list((root / "schema").glob("*.schema.json"))),
        "records_checked": records_checked,
        "schema_errors": schema_errors,
        "record_results": record_results,
        "status": "pass" if not schema_errors and not failures else "fail",
    }
    write_json(root / "validation-report.json", report)
    return report
