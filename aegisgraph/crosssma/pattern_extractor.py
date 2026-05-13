"""Finding -> canonical structural fingerprint.

CrossSMA's deduplication contract: two findings whose underlying
{pattern_type, family, axis, implementations} match (modulo casing
and order) MUST share a structural_signature. The signature is the
SHA-256 of a canonically-serialized JSON object so the same string
always yields the same hash byte-for-byte.

The fingerprint is what allows two SMAs that hit the same parser
divergence to dedup to one CrossSMA candidate rather than two
unrelated ones.

Contract:

  * `extract_pattern(finding) -> PatternFingerprint` accepts a dict
    carrying at minimum `pattern_type`, `family`, `axis`,
    `implementations` (a list of impl identifiers). Missing fields
    fall back to "unknown" so the function never raises on partial
    input -- callers that need strictness should validate upstream.
  * The canonical string used to hash is exposed as
    `PatternFingerprint.canonical_input` so reviewers can audit any
    signature by re-running `sha256_text(canonical_input)`.

The `pattern_type` MUST be one of the enum values from
`schema/cross-target-candidate.schema.json`. We don't enforce it
here (callers do), but the value flows directly into the rendered
evidence record, so a wrong value will fail schema validation
downstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from aegisgraph.io import canonical_json, sha256_text


VALID_PATTERN_TYPES = (
    "parser_disagreement",
    "invariant_violation",
    "harness_crash",
    "dependency_vulnerability",
    "structural_code_pattern",
)


@dataclass(frozen=True)
class PatternFingerprint:
    """Canonical fingerprint of a structural pattern.

    The `structural_signature` is the SHA-256 hex digest of
    `canonical_input`. Two equivalent fingerprints MUST share a
    signature so CrossSMA can dedupe candidates.
    """

    pattern_type: str
    family: str
    axis: str
    implementations: tuple[str, ...]
    canonical_input: str
    structural_signature: str


def _normalize_impl(impl: Any) -> str:
    """Normalize one implementation identifier:
    lowercase, strip surrounding whitespace, collapse internal whitespace.
    Aliases (`whatwg-url`, `WHATWG-URL`, ` whatwg url `) collapse to
    a single canonical token."""
    if not isinstance(impl, str):
        impl = str(impl)
    return " ".join(impl.lower().strip().split())


def _normalize_implementations(impls: Iterable[Any] | None) -> tuple[str, ...]:
    """Normalize + dedupe + sort the implementations list. Sorting is
    critical: ['A', 'B'] and ['B', 'A'] are the same set for our
    canonical-pattern purposes and must hash identically."""
    if not impls:
        return tuple()
    seen: set[str] = set()
    out: list[str] = []
    for impl in impls:
        norm = _normalize_impl(impl)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return tuple(sorted(out))


def _normalize_string_field(value: Any, default: str = "unknown") -> str:
    if value is None:
        return default
    s = str(value).strip()
    return s if s else default


def extract_pattern(finding: dict[str, Any]) -> PatternFingerprint:
    """Extract a canonical structural fingerprint from a finding dict.

    Accepts a partial finding -- missing fields fall back to "unknown"
    rather than raising. The caller is responsible for validating that
    `pattern_type` is one of `VALID_PATTERN_TYPES` before flowing the
    fingerprint into an AG-XSMA-* record (schema enforces it
    downstream, but failing earlier is friendlier).
    """
    pattern_type = _normalize_string_field(finding.get("pattern_type"))
    family = _normalize_string_field(finding.get("family"))
    axis = _normalize_string_field(finding.get("axis"))
    impls = _normalize_implementations(finding.get("implementations"))

    # Canonical-JSON the structural subset. Sorted keys + sorted impl
    # list together ensure that two structurally-equivalent findings
    # hit byte-identical canonical bytes.
    canonical_obj = {
        "pattern_type": pattern_type,
        "family": family,
        "axis": axis,
        "implementations_signature": list(impls),
    }
    canonical_bytes = canonical_json(canonical_obj)
    canonical_input = canonical_bytes.decode("utf-8")
    signature = sha256_text(canonical_input)

    return PatternFingerprint(
        pattern_type=pattern_type,
        family=family,
        axis=axis,
        implementations=impls,
        canonical_input=canonical_input,
        structural_signature=signature,
    )


__all__ = [
    "PatternFingerprint",
    "VALID_PATTERN_TYPES",
    "extract_pattern",
]
