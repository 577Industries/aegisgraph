from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .hashchain import verify_hash_chain
from .io import load_json, repo_root
from .safety import blocking_flags, scan_record
from .score import validate_score_vector


class ValidationFailure(Exception):
    pass


def schema_dir(root: Path | None = None) -> Path:
    return (root or repo_root()) / "schema"


def load_schema(name: str, root: Path | None = None) -> dict[str, Any]:
    return load_json(schema_dir(root) / name)


def validate_against_schema(instance: dict[str, Any], schema_name: str, root: Path | None = None) -> list[str]:
    schema = load_schema(schema_name, root)
    validator = Draft202012Validator(schema)
    return [f"{'/'.join(str(part) for part in error.path)}: {error.message}" for error in sorted(validator.iter_errors(instance), key=str)]


def check_schema_files(root: Path | None = None) -> list[str]:
    errors: list[str] = []
    for path in sorted(schema_dir(root).glob("*.schema.json")):
        try:
            Draft202012Validator.check_schema(load_json(path))
        except Exception as exc:  # pragma: no cover - exact jsonschema exception varies
            errors.append(f"{path.name}: {exc}")
    return errors


def validate_evidence_record(record: dict[str, Any], root: Path | None = None) -> list[str]:
    errors = validate_against_schema(record, "evidence.schema.json", root)
    errors.extend(validate_score_vector(record.get("score_vector", {})))
    errors.extend(verify_hash_chain(record))
    flags = scan_record(record)
    errors.extend(f"safety:{flag.rule}: {flag.message}" for flag in blocking_flags(flags))
    return errors


def assert_valid_evidence_record(record: dict[str, Any], root: Path | None = None) -> None:
    errors = validate_evidence_record(record, root)
    if errors:
        raise ValidationFailure("\n".join(errors))
