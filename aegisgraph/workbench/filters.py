"""Filter parsing for `aegisgraph workbench list / packet`.

`FindingFilters` is a frozen dataclass capturing engine / target /
claim-state predicates. `FilterSpec.parse` parses a comma-separated
``key=value`` expression (the form accepted by ``--filter`` on the CLI)
so reviewers can write::

    aegisgraph workbench packet --filter engine=polydiff,claim_state=reviewed

The parser is tolerant: empty strings, whitespace, and unknown keys are
ignored quietly (unknown keys would otherwise hard-fail the entire
packet build). All known keys accept a single value; future extension
to multi-value (CSV list per key) can be added without breaking the
single-value API.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Iterable


_RECOGNIZED_KEYS = frozenset({"engine", "target", "claim_state"})


@dataclass(frozen=True)
class FindingFilters:
    """Inclusive AND predicates used by registry + list + packet.

    `engine` matches the record's discovery_engine OR the registry-
    assigned engine bucket (extraction, polydiff, harnessgen,
    invariantcheck, crosssma, disclosure). `target` matches the
    record's target name OR a substring of repo_url. `claim_state`
    matches `claim_state` exactly (canonicalized).

    Any None field is a wildcard (no predicate).
    """

    engine: str | None = None
    target: str | None = None
    claim_state: str | None = None

    def matches(self, row: dict[str, Any]) -> bool:
        if self.engine is not None and not _engine_match(self.engine, row):
            return False
        if self.target is not None and not _target_match(self.target, row):
            return False
        if self.claim_state is not None and self.claim_state != row.get("claim_state"):
            return False
        return True

    def to_dict(self) -> dict[str, str]:
        out: dict[str, str] = {}
        if self.engine is not None:
            out["engine"] = self.engine
        if self.target is not None:
            out["target"] = self.target
        if self.claim_state is not None:
            out["claim_state"] = self.claim_state
        return out

    def with_update(self, **kwargs: Any) -> "FindingFilters":
        return replace(self, **kwargs)


def _engine_match(needle: str, row: dict[str, Any]) -> bool:
    needle_lower = needle.lower()
    for key in ("discovery_engine", "engine"):
        value = row.get(key)
        if isinstance(value, str) and value.lower() == needle_lower:
            return True
    return False


def _target_match(needle: str, row: dict[str, Any]) -> bool:
    """Tolerant target match: name or repo_url substring."""
    target = row.get("target")
    needle_lower = needle.lower()
    if isinstance(target, dict):
        name = str(target.get("name", "")).lower()
        repo = str(target.get("repo_url", "")).lower()
        if needle_lower in name or needle_lower in repo:
            return True
    target_id = row.get("target_id")
    if isinstance(target_id, str) and needle_lower in target_id.lower():
        return True
    return False


@dataclass(frozen=True)
class FilterSpec:
    """Parsed --filter expression. Keys: engine, target, claim_state.

    Use FilterSpec.parse(expr) for the CLI path; pass `.to_filters()`
    into list_findings / export_packet.
    """

    raw: str = ""
    pairs: dict[str, str] = field(default_factory=dict)

    @classmethod
    def parse(cls, expr: str | None) -> "FilterSpec":
        if expr is None or not expr.strip():
            return cls(raw="")
        pairs: dict[str, str] = {}
        for chunk in expr.split(","):
            chunk = chunk.strip()
            if not chunk or "=" not in chunk:
                continue
            key, _, value = chunk.partition("=")
            key = key.strip()
            value = value.strip()
            if not key or not value:
                continue
            if key not in _RECOGNIZED_KEYS:
                continue
            pairs[key] = value
        return cls(raw=expr, pairs=pairs)

    def to_filters(self) -> FindingFilters:
        return FindingFilters(
            engine=self.pairs.get("engine"),
            target=self.pairs.get("target"),
            claim_state=self.pairs.get("claim_state"),
        )


def filters_from_namespace(args: Any) -> FindingFilters:
    """Build a FindingFilters from an argparse.Namespace.

    Accepts None for missing attributes (graceful for the `show` /
    `promote` sub-subcommands that don't take all three flags).
    """
    return FindingFilters(
        engine=_get_optional_str(args, "engine"),
        target=_get_optional_str(args, "target"),
        claim_state=_get_optional_str(args, "claim_state"),
    )


def _get_optional_str(args: Any, attr: str) -> str | None:
    value = getattr(args, attr, None)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def filter_rows(
    rows: Iterable[dict[str, Any]], filters: FindingFilters
) -> list[dict[str, Any]]:
    return [row for row in rows if filters.matches(row)]
