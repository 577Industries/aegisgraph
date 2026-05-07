"""Rule-based security-relevance classifier.

Reads `polydiff/triage/rules.yml` and maps Disagreement records to
SecurityRelevance tags. Auditable, no ML, every rule traceable to a
public bug class. See SPEC §5.6.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# yaml is optional — fall back to a tiny inline parser for the very
# constrained rules.yml format we ship. This keeps the orchestrator
# importable without `pip install pyyaml`.
try:
    import yaml  # type: ignore[import-untyped]
except ImportError:
    yaml = None


@dataclass(frozen=True)
class Rule:
    rule_id: str
    axis: str
    when: str
    tags: list[str]
    description: str


def rules_path() -> Path:
    return Path(__file__).resolve().parent / "rules.yml"


def load_rules(path: Path | None = None) -> list[Rule]:
    """Load rules from `path` (default: polydiff/triage/rules.yml)."""
    p = path or rules_path()
    raw = p.read_text(encoding="utf-8")
    if yaml is not None:
        data = yaml.safe_load(raw)
    else:
        data = _tiny_yaml(raw)
    rules: list[Rule] = []
    for entry in data.get("rules", []):
        rules.append(
            Rule(
                rule_id=str(entry.get("id", "")),
                axis=str(entry.get("axis", "")),
                when=str(entry.get("when", "any-mismatch")),
                tags=list(entry.get("tags", []) or []),
                description=str(entry.get("description", "")).strip(),
            )
        )
    return rules


def classify(axis: str, values: set[Any], rules: list[Rule] | None = None) -> list[str]:
    """Return the tag list for a single disagreement (axis + observed values)."""
    rules = rules if rules is not None else load_rules()
    tags: list[str] = []
    seen: set[str] = set()
    for rule in rules:
        if rule.axis != axis:
            continue
        if not _rule_matches(rule.when, values):
            continue
        for tag in rule.tags:
            if tag not in seen:
                tags.append(tag)
                seen.add(tag)
    if not tags:
        tags.append("parser-behavior-difference")
    return tags


def _rule_matches(when: str, values: set[Any]) -> bool:
    if when == "any-mismatch":
        return True
    if when == "boolean-disagree":
        bools = {v for v in values if isinstance(v, bool)}
        return True in bools and False in bools
    if when == "null-vs-value":
        return any(v is None for v in values) and any(v is not None for v in values)
    return True


def _tiny_yaml(text: str) -> dict[str, Any]:
    """Tiny YAML reader for the very constrained rules.yml format.

    Supports:
      - top-level `rules:` list
      - per-rule `id:`, `axis:`, `when:`, `tags: [a, b]` or `tags:\\n  - a\\n  - b`
      - `description: >` followed by indented continuation lines.
      - line comments starting with `#`
    Not a general-purpose YAML parser; just enough to keep the
    orchestrator import-clean without pyyaml.
    """
    data: dict[str, Any] = {"rules": []}
    rules_list: list[dict[str, Any]] = data["rules"]
    current: dict[str, Any] | None = None
    pending_key: str | None = None
    pending_block: list[str] | None = None

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            if pending_block is not None:
                pending_block.append("")
            i += 1
            continue
        # close block-scalar on first non-indent, non-empty line
        indent = len(raw) - len(raw.lstrip(" "))
        if pending_block is not None and indent <= 4 and not raw.startswith("    "):
            assert current is not None and pending_key is not None
            current[pending_key] = " ".join(line.strip() for line in pending_block if line.strip())
            pending_block = None
            pending_key = None

        if stripped.startswith("- id:"):
            if current is not None:
                rules_list.append(current)
            current = {"id": stripped[len("- id:"):].strip()}
            i += 1
            continue
        if current is None and stripped == "rules:":
            i += 1
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", stripped)
        if not m:
            if pending_block is not None:
                pending_block.append(raw)
            i += 1
            continue
        key, value = m.group(1), m.group(2)
        if value == ">":
            pending_key = key
            pending_block = []
            i += 1
            continue
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            items = [x.strip() for x in inner.split(",") if x.strip()]
            if current is not None:
                current[key] = items
            else:
                data[key] = items
            i += 1
            continue
        if current is not None:
            current[key] = value.strip()
        else:
            data[key] = value.strip()
        i += 1

    # flush trailing block
    if pending_block is not None and current is not None and pending_key is not None:
        current[pending_key] = " ".join(line.strip() for line in pending_block if line.strip())

    if current is not None:
        rules_list.append(current)
    return data


__all__ = ["Rule", "classify", "load_rules", "rules_path"]
