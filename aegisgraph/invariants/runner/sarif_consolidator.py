"""SARIF -> AG-IV-* evidence-record consolidator.

Inputs:
  * `sarif`        — a parsed SARIF 2.1.0 document (dict; from json.load).
  * `target`       — {target_id, repo_url, commit}: identifies the SMA the
                     SARIF was produced against.
  * `rule_to_invariant` — {sarif_rule_id: invariant_id} mapping. Used to:
                     (a) filter SARIF results to only OUR invariants
                         (anything else is some other CodeQL pack);
                     (b) attach the canonical `INV-NN` to each emitted
                         record.
  * `sarif_result_uri` — repo-relative path pointing back to the SARIF
                     file on disk. Per the invariant-violation schema
                     and sanitize-check Rule 8, the AG-IV-* record
                     carries this URI, NOT the SARIF content itself —
                     SARIF lives engineering-private and only the record
                     is exportable.
  * `rule_engine`  — "codeql" | "semgrep" | "frida_dynamic". The runner
                     calling us knows which engine produced the SARIF.
  * `discovery_run_id` — optional discovery_run record id this run is
                     attached to (carried for traceability into the
                     evidence graph).

Outputs:
  * `list[dict]` — one AG-IV-* record per SARIF result that matched a
                   mapped rule. Each record validates against
                   `schema/invariant-violation.schema.json`.

Determinism guarantees:
  * `violation_id` is a sha256-based short hash of the SARIF
    (target_id, invariant_id, path, start_line, rule_id) tuple — same
    input -> same id, across runs and machines.
  * `hash_chain` uses `aegisgraph.hashchain` canonicalization.
  * `provenance.generated_at` comes from
    `aegisgraph.constants.STATIC_GENERATED_AT` so re-runs hash identically.

Sanitize-check compliance (Rule 8):
  * The record's `location` carries (repo_url, commit, path, start_line)
    only — never multi-line code snippets. SARIF snippets and message
    text are NOT propagated into the public record fields (the `message`
    field is treated as a short human-readable label, truncated).
"""

from __future__ import annotations

from typing import Any

from ...constants import STATIC_GENERATED_AT
from ...hashchain import attach_hash_chain
from ...io import sha256_text


_SUPPORTED_ENGINES = frozenset({"codeql", "semgrep", "frida_dynamic"})
_VALID_SEVERITIES = frozenset({"error", "warning", "note", "none"})
_SARIF_DEFAULT_LEVEL = "warning"  # per SARIF 2.1.0 §3.27.10


def _violation_id(
    target_id: str,
    invariant_id: str,
    rule_id: str,
    path: str,
    start_line: int,
) -> str:
    """Build a deterministic AG-IV-* id.

    Pattern (matches `^AG-IV-[A-Z0-9-]+$` in
    schema/invariant-violation.schema.json):

        AG-IV-<INVNN>-<SHA12>

    where SHA12 is the first 12 hex chars of a sha256 over the
    (target_id|invariant_id|rule_id|path|start_line) tuple. We uppercase
    the result because the schema regex is uppercase-only.
    """
    raw = "|".join([target_id, invariant_id, rule_id, path, str(start_line)])
    digest = sha256_text(raw)[:12].upper()
    # Strip "INV-" prefix so we don't double up: AG-IV-01-... not AG-IV-INV-01-...
    inv_short = invariant_id.replace("INV-", "")
    return f"AG-IV-{inv_short}-{digest}"


def _rules_by_index(run: dict[str, Any]) -> list[str]:
    """Build the SARIF rule-index -> rule-id lookup.

    SARIF results may reference a rule by `ruleId` (direct) OR by
    `ruleIndex` (offset into the run.tool.driver.rules array). Real
    CodeQL output sometimes uses the index form; we support both.
    """
    driver = run.get("tool", {}).get("driver", {}) or {}
    rules = driver.get("rules", []) or []
    out: list[str] = []
    for rule in rules:
        if isinstance(rule, dict):
            out.append(str(rule.get("id", "")))
        else:
            out.append("")
    return out


def _extract_location(result: dict[str, Any]) -> tuple[str, int, int | None] | None:
    """Pull (path, start_line, start_column?) from the first SARIF location.

    Returns None if the result has no locations or the first location has
    no usable path — the consolidator will skip such results because the
    record schema requires `location.path` and `location.start_line`.
    """
    locations = result.get("locations") or []
    if not locations:
        return None
    pl = (locations[0] or {}).get("physicalLocation") or {}
    art = pl.get("artifactLocation") or {}
    uri = str(art.get("uri", "") or "")
    if not uri:
        return None
    region = pl.get("region") or {}
    start_line = region.get("startLine")
    if isinstance(start_line, str) and start_line.isdigit():
        start_line = int(start_line)
    if not isinstance(start_line, int) or start_line < 1:
        # SARIF allows omitting startLine for file-level results, but our
        # schema requires start_line >= 1. We could synthesize 1, but
        # consolidator-wide policy is: skip rather than fabricate.
        return None
    start_column = region.get("startColumn")
    if isinstance(start_column, str) and start_column.isdigit():
        start_column = int(start_column)
    if not isinstance(start_column, int) or start_column < 1:
        start_column = None
    return uri, start_line, start_column


def _provenance(rule_engine: str) -> dict[str, Any]:
    return {
        "generated_by": "aegisgraph-invariants",
        "generated_at": STATIC_GENERATED_AT,
        "source": f"aegisgraph.invariants.runner.{rule_engine}_runner",
        "private_by_default": True,
    }


def _truncate_message(text: str, limit: int = 240) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def consolidate_sarif(
    *,
    sarif: dict[str, Any],
    target: dict[str, str],
    rule_to_invariant: dict[str, str],
    sarif_result_uri: str,
    rule_engine: str,
    discovery_run_id: str | None = None,
) -> list[dict[str, Any]]:
    """Convert SARIF results into a list of AG-IV-* evidence records.

    See module docstring for the full contract. Returns an empty list if
    `sarif` is empty/malformed/has no matching rules — never raises on
    plausible inputs.
    """
    if rule_engine not in _SUPPORTED_ENGINES:
        raise ValueError(
            f"unknown rule_engine {rule_engine!r}; "
            f"expected one of {sorted(_SUPPORTED_ENGINES)}"
        )

    if not isinstance(sarif, dict):
        return []

    target_id = str(target.get("target_id", "")).strip()
    repo_url = str(target.get("repo_url", "")).strip()
    commit = str(target.get("commit", "")).strip()
    if not (target_id and repo_url and commit):
        # Caller passed an incomplete target; we cannot anchor the record
        # because the schema requires repo_url, commit, and target_id.
        return []

    records: list[dict[str, Any]] = []
    runs = sarif.get("runs") or []
    if not isinstance(runs, list):
        return []

    for run in runs:
        if not isinstance(run, dict):
            continue
        index_lookup = _rules_by_index(run)
        results = run.get("results") or []
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId")
            if not rule_id:
                idx = result.get("ruleIndex")
                if isinstance(idx, int) and 0 <= idx < len(index_lookup):
                    rule_id = index_lookup[idx]
            if not rule_id:
                continue
            invariant_id = rule_to_invariant.get(str(rule_id))
            if not invariant_id:
                # SARIF result is for some other rule — not in our library.
                continue

            loc = _extract_location(result)
            if loc is None:
                continue
            path, start_line, start_column = loc

            level = str(result.get("level") or _SARIF_DEFAULT_LEVEL)
            if level not in _VALID_SEVERITIES:
                level = "warning"

            message_text = (
                (result.get("message") or {}).get("text")
                if isinstance(result.get("message"), dict)
                else None
            )
            message = _truncate_message(str(message_text or ""))

            location_obj: dict[str, Any] = {
                "repo_url": repo_url,
                "commit": commit,
                "path": path,
                "start_line": start_line,
                "end_line": None,
                "start_column": start_column,
            }

            violation_id = _violation_id(
                target_id, invariant_id, str(rule_id), path, start_line
            )

            record: dict[str, Any] = {
                "violation_id": violation_id,
                "version": "v1.0",
                "discovery_engine": "invariantcheck",
                "invariant_id": invariant_id,
                "target_id": target_id,
                "discovery_run_id": discovery_run_id,
                "rule_id": str(rule_id),
                "rule_engine": rule_engine,
                "severity": level,
                "location": location_obj,
                "sarif_result_uri": sarif_result_uri,
                "message": message or None,
                "mastg_mapping": None,
                "ssdf_mapping": None,
                "applicable_path_classes": [],
                "provenance": _provenance(rule_engine),
            }

            # Seal with hash-chain. We do NOT call evidence.finalize_record
            # here because the invariant-violation schema is its own shape
            # (it does not have `safety_flags` / `recommendation_refs`);
            # finalize_record was designed for the v1 evidence record. We
            # apply hash-chain directly. Safety flags would be applied at
            # the export boundary if these records are ever exported.
            sealed = attach_hash_chain(record)
            records.append(sealed)

    return records


__all__ = ["consolidate_sarif"]
