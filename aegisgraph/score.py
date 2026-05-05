from __future__ import annotations

from .constants import SCORE_DIMENSIONS


def score_total(score_vector: dict[str, float]) -> float:
    return round(sum(float(score_vector[dimension]) for dimension in SCORE_DIMENSIONS), 3)


def normalize_score_vector(values: dict[str, float]) -> dict[str, float]:
    vector = {dimension: round(float(values.get(dimension, 0.0)), 3) for dimension in SCORE_DIMENSIONS}
    vector["total"] = score_total(vector)
    return vector


def validate_score_vector(score_vector: dict[str, float]) -> list[str]:
    errors: list[str] = []
    for dimension in SCORE_DIMENSIONS:
        value = score_vector.get(dimension)
        if not isinstance(value, (int, float)) or value < 0 or value > 1:
            errors.append(f"{dimension} must be a number in [0, 1]")
    expected = score_total(score_vector)
    actual = round(float(score_vector.get("total", -1)), 3)
    if expected != actual:
        errors.append(f"score total mismatch: expected {expected}, found {actual}")
    return errors


def media_parser_score() -> dict[str, float]:
    return normalize_score_vector(
        {
            "remote_reachability": 0.9,
            "attacker_control": 0.9,
            "parser_complexity": 0.8,
            "native_boundary": 0.8,
            "auth_boundary": 0.6,
            "privilege_impact": 0.7,
            "exploit_history": 0.9,
            "mitigation_strength": 0.5,
            "observability": 0.4,
            "confidence": 0.55,
        }
    )


def link_parser_score() -> dict[str, float]:
    return normalize_score_vector(
        {
            "remote_reachability": 0.8,
            "attacker_control": 0.85,
            "parser_complexity": 0.65,
            "native_boundary": 0.15,
            "auth_boundary": 0.55,
            "privilege_impact": 0.55,
            "exploit_history": 0.7,
            "mitigation_strength": 0.45,
            "observability": 0.6,
            "confidence": 0.6,
        }
    )
