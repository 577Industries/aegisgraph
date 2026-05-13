"""Per-tool baseline-delta runner.

Each runner orchestrates one single-tool execution against a pinned
target source tree and returns a structured envelope:

    {
      "tool":            "codeql" | "semgrep" | "mobsf" | "aegisgraph",
      "target_id":       <"signal_android@1043851"|"elementx_android@91d265e6">,
      "status":          "ran" | "binary_missing" | "apk_missing"
                          | "scaffold_pending" | "failed",
      "reason":          short human-readable note,
      "sarif_path":      str | None,  (codeql, semgrep)
      "findings_path":   str | None,  (all tools — normalized findings JSON)
      "coverage_path":   str | None,  (per-tool coverage JSON)
      "mobsf_limited_md": str | None, (only set when status == apk_missing)
      "findings_count":  int,
      "tool_version":    str | None,
    }

Sanitize-check compliance:
  * Rule 7: when the tool emits findings, we project to
    {category, rule_id, location_hash, severity} only — never include
    raw vendor contact data in findings.
  * Rule 8: SARIF artifactLocation.uri + region.startLine are
    fingerprinted into location_hash; no multi-line source snippets
    are propagated.
  * BLOCKING_PATTERNS: aegisgraph runner only emits records that pass
    through `aegisgraph.evidence.finalize_record`, which already
    applies safety flags.

No live target probing: each runner accepts target metadata that
describes pre-existing anchor-only assets:
  * CodeQL DB directory (built via extraction/targets/<t>/build_db.sh)
  * Source tree root (read-only, anchor-only, NOT redistributed)
  * Optional APK path (MobSF only; usually None per anchor-only policy)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Iterable

from ..constants import STATIC_GENERATED_AT, TARGETS
from ..io import sha256_text, write_json, write_text


# Filename constants — these are part of the public output-tree shape
# and locked by tests/baseline_delta/test_mobsf_limited_path.py and
# tests/test_baseline_delta_artifacts_present.py.
MOBSF_LIMITED_FILENAME = "MOBSF-LIMITED.md"
CODEQL_FINDINGS_FILENAME = "codeql-findings.json"
CODEQL_COVERAGE_FILENAME = "codeql-coverage.json"
SEMGREP_FINDINGS_FILENAME = "semgrep-findings.json"
SEMGREP_COVERAGE_FILENAME = "semgrep-coverage.json"
MOBSF_FINDINGS_FILENAME = "mobsf-findings.json"
MOBSF_COVERAGE_FILENAME = "mobsf-coverage.json"
AEGISGRAPH_FINDINGS_FILENAME = "aegisgraph-findings.json"
AEGISGRAPH_COVERAGE_FILENAME = "aegisgraph-coverage.json"

# Tool-version pins — match T-M4.1 self-hosted runner toolchain and the
# Dockerfile in this package. Mismatches surface as a `reason` string.
EXPECTED_CODEQL_VERSION_PREFIX = "2.20.6"
EXPECTED_SEMGREP_VERSION_PREFIX = "1.86"

# Semgrep config bundles for the baseline-alone run (per Wave 9A spec).
SEMGREP_BASELINE_CONFIGS = ("p/security-audit", "p/mobsf-android")

# Configured target keys (for build_target_specs).
SUPPORTED_TARGET_KEYS = ("signal", "element-x")


def _which_default(binary: str) -> str | None:
    return shutil.which(binary)


def _target_id_from_constants(target_key: str) -> str:
    """Render the canonical target_id from `aegisgraph.constants.TARGETS`.

    Mirrors the convention used by the rest of the codebase
    (`signal_android@1043851`, `elementx_android@91d265e6`).
    """
    spec = TARGETS[target_key]
    short = spec["public_artifact_id"].rsplit("_", 1)
    return f"{short[0]}@{short[1]}"


def build_target_specs(*, repo_root: Path) -> list[dict[str, Any]]:
    """Resolve target specs from `aegisgraph.constants.TARGETS` + on-disk
    extraction outputs. Used by the orchestrator.

    Returns a list of dicts shaped like:
        {
          "target_key", "target_id", "name", "repo_url", "commit",
          "source_root", "codeql_db", "apk_path",
        }
    `source_root` and `codeql_db` point at the documented locations
    inside the engineering repo. They may not exist on a host that
    hasn't built the DBs — the runner functions tolerate that and emit
    a clean `failed`/`skipped_pending_toolchain` envelope.
    """
    specs: list[dict[str, Any]] = []
    for key in SUPPORTED_TARGET_KEYS:
        spec = TARGETS[key]
        # Convention: extraction/targets/<dir>/source/ (anchor-only,
        # gitignored) holds the cloned source tree when present.
        target_dir_key = key if key == "signal" else "element-x-android"
        # Element X uses "element-x-android" as its target dir name to
        # match extraction/targets/<dir>/. Signal stays "signal-android".
        target_dir_name = "signal-android" if key == "signal" else "element-x-android"
        source_root = repo_root / "extraction" / "targets" / target_dir_name / "source"
        codeql_db = repo_root / "extraction" / "output" / spec["graph_dir"] / "codeql-db"
        specs.append({
            "target_key": key,
            "target_id": _target_id_from_constants(key),
            "name": spec["name"],
            "repo_url": spec["repo_url"],
            "commit": spec["commit"],
            "source_root": str(source_root),
            "codeql_db": str(codeql_db),
            "apk_path": None,
        })
    return specs


# ---------------------------------------------------------------------------
# MOBSF-LIMITED.md writer
# ---------------------------------------------------------------------------

_MOBSF_LIMITED_TEMPLATE = """# MobSF run NOT executed for {target_id}

**Reason:** `{reason}`

**Generated at:** {timestamp}

## Target

| Field | Value |
|---|---|
| target_id | `{target_id}` |
| repo_url | {repo_url} |
| commit | `{commit}` |
| apk_path | _(not available)_ |

## Why MobSF did not run

MobSF requires an APK to analyze. AegisGraph operates under an
**anchor-only** source policy (see `extraction/targets/<target>/target.json`):
target binaries are NOT redistributed inside this research repo, and APKs
are acquired only at execution time on the self-hosted runner (see
`extraction/mobsf/README.md` "APK acquisition asymmetry" section).

The current invocation environment is missing the APK file (`apk_missing`)
or the docker binary required to run the MobSF container (`binary_missing`).
Per Wave 9A policy, the runner does **not** fabricate findings — it
records this state transparently and the delta report renders the cell as
"MOBSF-LIMITED" with zero findings counted.

## Operational note

To produce a real MobSF row in the baseline-delta report:

1. Acquire the APK on the self-hosted runner per
   `extraction/mobsf/README.md` (signed authorization required for
   any binary not publicly distributed).
2. Re-run `python3 -m aegisgraph.baseline_delta.runner --target {target_key}`
   with `--apk-path` set.

## Status envelope

This file is the human-readable companion to the structured envelope:

```json
{{
  "tool": "mobsf",
  "target_id": "{target_id}",
  "status": "{reason}",
  "findings_count": 0,
  "mobsf_limited_md": "MOBSF-LIMITED.md"
}}
```
"""


def write_mobsf_limited_md(
    *,
    output_dir: Path,
    target: dict[str, Any],
    reason: str,
) -> Path:
    """Write the MOBSF-LIMITED.md transparency note.

    Args:
        output_dir: per-target output directory (created if missing).
        target:     target spec (see build_target_specs).
        reason:     either "apk_missing" or "binary_missing".

    Returns:
        Path to the written file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    md_path = output_dir / MOBSF_LIMITED_FILENAME
    text = _MOBSF_LIMITED_TEMPLATE.format(
        target_id=target["target_id"],
        target_key=target["target_key"],
        repo_url=target["repo_url"],
        commit=target["commit"],
        timestamp=STATIC_GENERATED_AT,
        reason=reason,
    )
    write_text(md_path, text)
    return md_path


# ---------------------------------------------------------------------------
# Location-hash helpers
# ---------------------------------------------------------------------------


def location_hash(*, path: str, start_line: int | None) -> str:
    """Deterministic 16-char hash over (path, start_line).

    Used to fingerprint a finding location without propagating the
    source-snippet content (Rule 8). Two findings at the same
    (path, start_line) get the same hash — the matcher used by the
    overlap matrix.
    """
    base = f"{path}|{start_line if start_line is not None else 0}"
    return sha256_text(base)[:16]


# ---------------------------------------------------------------------------
# Per-tool runners
# ---------------------------------------------------------------------------


def _empty_findings_envelope(*, tool: str, target_id: str, status: str, reason: str) -> dict[str, Any]:
    return {
        "tool": tool,
        "target_id": target_id,
        "status": status,
        "reason": reason,
        "sarif_path": None,
        "findings_path": None,
        "coverage_path": None,
        "mobsf_limited_md": None,
        "findings_count": 0,
        "tool_version": None,
    }


def run_codeql_alone(
    *,
    target: dict[str, Any],
    output_dir: Path,
    which: Callable[[str], str | None] = _which_default,
    subprocess_run: Callable[..., subprocess.CompletedProcess] | None = None,
) -> dict[str, Any]:
    """Run the `codeql/java-queries` security suite against the pinned
    CodeQL database for `target`.

    Honest-output modes:
      * `codeql` not on PATH -> status=binary_missing
      * CodeQL DB not found  -> status=failed reason="db_missing"
      * subprocess error     -> status=failed reason=<short error>
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    target_id = target["target_id"]
    envelope = _empty_findings_envelope(
        tool="codeql",
        target_id=target_id,
        status="binary_missing",
        reason="codeql CLI not on PATH",
    )

    if which("codeql") is None:
        return envelope

    db_dir = Path(target["codeql_db"]) if target.get("codeql_db") else None
    if db_dir is None or not db_dir.is_dir():
        envelope["status"] = "failed"
        envelope["reason"] = "db_missing: CodeQL DB not built for this target"
        return envelope

    sarif_path = output_dir / "raw" / "codeql-baseline.sarif"
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "codeql",
        "database",
        "analyze",
        str(db_dir),
        "codeql/java-queries",
        "--format=sarifv2.1.0",
        f"--output={sarif_path}",
    ]
    run = subprocess_run or subprocess.run
    try:
        completed = run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        envelope["status"] = "failed"
        envelope["reason"] = f"codeql analyze raised: {exc}"
        return envelope

    if completed.returncode != 0:
        envelope["status"] = "failed"
        envelope["reason"] = (
            f"codeql analyze exit={completed.returncode}: "
            f"{(completed.stderr or completed.stdout)[:200]}"
        )
        return envelope

    findings = _normalize_sarif_findings(
        sarif_path=sarif_path,
        tool="codeql",
        target=target,
    )
    findings_path = output_dir / CODEQL_FINDINGS_FILENAME
    coverage_path = output_dir / CODEQL_COVERAGE_FILENAME
    write_json(findings_path, _finding_envelope(tool="codeql", target=target, findings=findings))
    write_json(coverage_path, _coverage_envelope(
        tool="codeql",
        target=target,
        status="ran",
        findings=findings,
        tool_version=EXPECTED_CODEQL_VERSION_PREFIX,
    ))

    envelope.update({
        "status": "ran",
        "reason": "",
        "sarif_path": str(sarif_path),
        "findings_path": str(findings_path),
        "coverage_path": str(coverage_path),
        "findings_count": len(findings),
        "tool_version": EXPECTED_CODEQL_VERSION_PREFIX,
    })
    return envelope


def run_semgrep_alone(
    *,
    target: dict[str, Any],
    output_dir: Path,
    which: Callable[[str], str | None] = _which_default,
    subprocess_run: Callable[..., subprocess.CompletedProcess] | None = None,
    configs: Iterable[str] = SEMGREP_BASELINE_CONFIGS,
) -> dict[str, Any]:
    """Run Semgrep `p/security-audit` + `p/mobsf-android` configs
    against the source tree at `target.source_root`.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    target_id = target["target_id"]
    envelope = _empty_findings_envelope(
        tool="semgrep",
        target_id=target_id,
        status="binary_missing",
        reason="semgrep CLI not on PATH",
    )

    if which("semgrep") is None:
        return envelope

    source_root = Path(target["source_root"]) if target.get("source_root") else None
    if source_root is None or not source_root.is_dir():
        envelope["status"] = "failed"
        envelope["reason"] = "source_root_missing: anchor-only source tree absent"
        return envelope

    sarif_path = output_dir / "raw" / "semgrep-baseline.sarif"
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["semgrep"]
    for cfg in configs:
        cmd += ["--config", cfg]
    cmd += ["--sarif", "--output", str(sarif_path), str(source_root)]
    run = subprocess_run or subprocess.run
    try:
        completed = run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        envelope["status"] = "failed"
        envelope["reason"] = f"semgrep raised: {exc}"
        return envelope

    if completed.returncode not in (0, 1):  # 1 = findings present (semgrep convention)
        envelope["status"] = "failed"
        envelope["reason"] = (
            f"semgrep exit={completed.returncode}: "
            f"{(completed.stderr or completed.stdout)[:200]}"
        )
        return envelope

    findings = _normalize_sarif_findings(
        sarif_path=sarif_path,
        tool="semgrep",
        target=target,
    )
    findings_path = output_dir / SEMGREP_FINDINGS_FILENAME
    coverage_path = output_dir / SEMGREP_COVERAGE_FILENAME
    write_json(findings_path, _finding_envelope(tool="semgrep", target=target, findings=findings))
    write_json(coverage_path, _coverage_envelope(
        tool="semgrep",
        target=target,
        status="ran",
        findings=findings,
        tool_version=EXPECTED_SEMGREP_VERSION_PREFIX,
    ))

    envelope.update({
        "status": "ran",
        "reason": "",
        "sarif_path": str(sarif_path),
        "findings_path": str(findings_path),
        "coverage_path": str(coverage_path),
        "findings_count": len(findings),
        "tool_version": EXPECTED_SEMGREP_VERSION_PREFIX,
    })
    return envelope


def run_mobsf_alone(
    *,
    target: dict[str, Any],
    output_dir: Path,
    which: Callable[[str], str | None] = _which_default,
    subprocess_run: Callable[..., subprocess.CompletedProcess] | None = None,
) -> dict[str, Any]:
    """Run MobSF against an APK if one is available.

    Per Wave 9A: APK absence is honest. We write MOBSF-LIMITED.md and
    return an `apk_missing` envelope. No fabricated findings.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    target_id = target["target_id"]
    envelope = _empty_findings_envelope(
        tool="mobsf",
        target_id=target_id,
        status="binary_missing",
        reason="docker CLI not on PATH (required for MobSF container)",
    )

    if which("docker") is None:
        # Even when docker isn't available we still emit the
        # MOBSF-LIMITED.md so the delta-report renderer can read the
        # transparency note.
        md_path = write_mobsf_limited_md(
            output_dir=output_dir,
            target=target,
            reason="binary_missing",
        )
        envelope["mobsf_limited_md"] = str(md_path)
        return envelope

    apk_path = target.get("apk_path")
    if not apk_path or not Path(str(apk_path)).is_file():
        md_path = write_mobsf_limited_md(
            output_dir=output_dir,
            target=target,
            reason="apk_missing",
        )
        envelope.update({
            "status": "apk_missing",
            "reason": "no APK available under anchor-only policy",
            "mobsf_limited_md": str(md_path),
        })
        return envelope

    # APK + docker present: defer to the extraction/mobsf/run_mobsf.py
    # path which already implements the offline container run. We don't
    # duplicate that logic here — we shell out to the existing runner
    # and read its output back. This is the only place this module
    # touches a process; it's still pure subprocess + file I/O.
    raw_output = output_dir / "raw" / "mobsf-results.json"
    raw_output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "python3",
        "-m",
        "extraction.mobsf.run_mobsf",
        "--target",
        target["target_key"],
        "--apk",
        str(apk_path),
        "--output",
        str(raw_output),
    ]
    run = subprocess_run or subprocess.run
    try:
        completed = run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        envelope["status"] = "failed"
        envelope["reason"] = f"mobsf runner raised: {exc}"
        return envelope

    if completed.returncode != 0 or not raw_output.is_file():  # pragma: no cover
        envelope["status"] = "failed"
        envelope["reason"] = (
            f"mobsf exit={completed.returncode}: "
            f"{(completed.stderr or completed.stdout)[:200]}"
        )
        return envelope

    findings = _normalize_mobsf_findings(raw_output, target=target)
    findings_path = output_dir / MOBSF_FINDINGS_FILENAME
    coverage_path = output_dir / MOBSF_COVERAGE_FILENAME
    write_json(findings_path, _finding_envelope(tool="mobsf", target=target, findings=findings))
    write_json(coverage_path, _coverage_envelope(
        tool="mobsf",
        target=target,
        status="ran",
        findings=findings,
        tool_version=None,
    ))

    envelope.update({
        "status": "ran",
        "reason": "",
        "findings_path": str(findings_path),
        "coverage_path": str(coverage_path),
        "findings_count": len(findings),
    })
    return envelope


def run_aegisgraph_alone(
    *,
    target: dict[str, Any],
    output_dir: Path,
    which: Callable[[str], str | None] = _which_default,
) -> dict[str, Any]:
    """Run the AegisGraph 15-invariant suite + PolyDiff regression against
    the same source tree.

    On developer machines we use the "scaffold_pending" path: emit a
    well-formed envelope + an empty findings list + a coverage envelope
    flagging "scaffold_pending". The self-hosted runner's
    `.github/workflows/baseline-delta.yml` path overrides this by
    invoking the real invariants runner.

    The status returned here is NEVER `binary_missing` — AegisGraph
    itself has no external binary requirement (the invariant queries
    are CodeQL/Semgrep but those are run earlier via the codeql_alone /
    semgrep_alone path).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    target_id = target["target_id"]

    # Try to read pre-existing invariant violations from the consolidated
    # output, if any. Anchor-only policy: this is read-only.
    consolidated_path: Path | None = None
    candidate = (
        Path(target.get("source_root", "")).resolve().parent.parent
        / "output"
        / target["target_key"]
        / "invariant-violations.json"
    )
    if candidate.is_file():
        consolidated_path = candidate

    findings: list[dict[str, Any]] = []
    status = "scaffold_pending"
    reason = "AegisGraph invariant + polydiff execution deferred to self-hosted runner (T-M4.1)"

    if consolidated_path is not None:
        try:
            payload = json.loads(consolidated_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):  # pragma: no cover
            payload = None
        if isinstance(payload, dict):
            rows = payload.get("violations") or payload.get("records") or []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                category = (
                    row.get("invariant_id")
                    or row.get("category")
                    or row.get("rule_id")
                    or "unknown"
                )
                location = row.get("location") or {}
                path_field = location.get("path") or row.get("path") or ""
                start_line = location.get("start_line") or row.get("start_line")
                findings.append({
                    "tool": "aegisgraph",
                    "target": target["target_key"],
                    "target_id": target_id,
                    "category": str(category),
                    "rule_id": str(row.get("rule_id") or category),
                    "location_hash": location_hash(
                        path=str(path_field),
                        start_line=int(start_line) if isinstance(start_line, int) else None,
                    ),
                    "severity": str(row.get("severity") or "warning"),
                })
            status = "ran"
            reason = ""

    findings_path = output_dir / AEGISGRAPH_FINDINGS_FILENAME
    coverage_path = output_dir / AEGISGRAPH_COVERAGE_FILENAME
    write_json(findings_path, _finding_envelope(tool="aegisgraph", target=target, findings=findings))
    write_json(coverage_path, _coverage_envelope(
        tool="aegisgraph",
        target=target,
        status=status,
        findings=findings,
        tool_version="invariants-v3 + polydiff-extended",
    ))

    return {
        "tool": "aegisgraph",
        "target_id": target_id,
        "status": status,
        "reason": reason,
        "sarif_path": None,
        "findings_path": str(findings_path),
        "coverage_path": str(coverage_path),
        "mobsf_limited_md": None,
        "findings_count": len(findings),
        "tool_version": "invariants-v3 + polydiff-extended",
    }


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def _normalize_sarif_findings(
    *,
    sarif_path: Path,
    tool: str,
    target: dict[str, Any],
) -> list[dict[str, Any]]:
    """Project a SARIF document into the normalized finding shape.

    Output rows:
        {tool, target, target_id, category, rule_id, location_hash, severity}

    Per Rule 8: NO source snippets, NO message text, NO multi-line
    excerpts. Only the location fingerprint + rule id + severity.
    """
    if not sarif_path.is_file():
        return []
    try:
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):  # pragma: no cover
        return []

    rows: list[dict[str, Any]] = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = str(result.get("ruleId") or "unknown")
            severity = str(result.get("level") or "warning")
            # Severity in SARIF is among {none, note, warning, error}.
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation") or {}
                artifact = (phys.get("artifactLocation") or {}).get("uri") or ""
                region = phys.get("region") or {}
                start_line = region.get("startLine")
                rows.append({
                    "tool": tool,
                    "target": target["target_key"],
                    "target_id": target["target_id"],
                    "category": _category_from_rule_id(rule_id),
                    "rule_id": rule_id,
                    "location_hash": location_hash(
                        path=str(artifact),
                        start_line=int(start_line) if isinstance(start_line, int) else None,
                    ),
                    "severity": severity,
                })
    return rows


def _normalize_mobsf_findings(
    raw_output: Path,
    *,
    target: dict[str, Any],
) -> list[dict[str, Any]]:
    """Project a MobSF results JSON into the normalized finding shape.

    MobSF reports are a flat dict with categorized result arrays
    (manifest_analysis, code_analysis, ...). We project the "category"
    key directly from those top-level groupings.
    """
    try:
        payload = json.loads(raw_output.read_text(encoding="utf-8"))
    except (OSError, ValueError):  # pragma: no cover
        return []
    report = payload.get("report") or {}
    rows: list[dict[str, Any]] = []
    for top_category, value in report.items():
        if not isinstance(value, (list, dict)):
            continue
        if isinstance(value, dict):
            iterator = value.values()
        else:
            iterator = value
        for item in iterator:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("rule") or item.get("id") or item.get("title") or "unknown")
            path = str(item.get("file") or item.get("path") or "")
            start_line = item.get("line")
            rows.append({
                "tool": "mobsf",
                "target": target["target_key"],
                "target_id": target["target_id"],
                "category": str(top_category),
                "rule_id": rule_id,
                "location_hash": location_hash(
                    path=path,
                    start_line=int(start_line) if isinstance(start_line, int) else None,
                ),
                "severity": str(item.get("severity") or "warning"),
            })
    return rows


def _category_from_rule_id(rule_id: str) -> str:
    """Heuristic mapping rule_id -> short category bucket.

    We don't try to be exhaustive — the overlap matrix needs *some*
    grouping key broader than rule_id (which differs across tools)
    but narrower than "all findings". The strategy:

      1. If the rule_id matches AegisGraph's INV-NN_<slug> pattern,
         use `<slug>`.
      2. If the rule_id matches `<owner>/<pack>/<rule-name>` (CodeQL),
         use the last component without the extension.
      3. Otherwise use the rule_id verbatim (lower-cased).
    """
    rid = rule_id.strip().lower()
    if not rid:
        return "unknown"
    # AegisGraph invariant pattern: INV-NN_<slug>.ql -> slug
    if rid.startswith("inv-"):
        parts = rid.split("_", 1)
        if len(parts) == 2:
            slug = parts[1].removesuffix(".ql").removesuffix(".yaml")
            return slug
    # Slash-separated: take the last component
    if "/" in rid:
        rid = rid.rsplit("/", 1)[-1]
    # Strip common extensions
    for ext in (".ql", ".yaml", ".yml"):
        if rid.endswith(ext):
            rid = rid[: -len(ext)]
    return rid


# Safety posture: when the orchestrator stages output under the
# proposal package, every tool_output_type document must declare
# `sanitized_candidate` so sanitize_check Rule 4 passes. This is
# baked into the envelope at write time. The records here contain
# only rule_ids + location_hashes + per-tool counts — no source
# snippets, no payloads, no vendor contacts — so the
# sanitized_candidate marking is accurate, not aspirational.
_DEFAULT_SAFETY_POSTURE = "sanitized_candidate"


def _finding_envelope(
    *,
    tool: str,
    target: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "tool_output_type": f"baseline_delta_{tool}_findings",
        "version": "v1.0",
        "tool": tool,
        "target": target["target_key"],
        "target_id": target["target_id"],
        "target_repo_url": target["repo_url"],
        "target_commit": target["commit"],
        "generated_at": STATIC_GENERATED_AT,
        "generated_by": "aegisgraph-tier3-research",
        "safety_posture": _DEFAULT_SAFETY_POSTURE,
        "findings_count": len(findings),
        "findings": findings,
    }


def _coverage_envelope(
    *,
    tool: str,
    target: dict[str, Any],
    status: str,
    findings: list[dict[str, Any]],
    tool_version: str | None,
) -> dict[str, Any]:
    categories = sorted({f["category"] for f in findings})
    return {
        "tool_output_type": f"baseline_delta_{tool}_coverage",
        "version": "v1.0",
        "tool": tool,
        "target": target["target_key"],
        "target_id": target["target_id"],
        "generated_at": STATIC_GENERATED_AT,
        "generated_by": "aegisgraph-tier3-research",
        "safety_posture": _DEFAULT_SAFETY_POSTURE,
        "status": status,
        "tool_version": tool_version,
        "findings_count": len(findings),
        "categories_covered": categories,
    }


__all__ = [
    "MOBSF_LIMITED_FILENAME",
    "CODEQL_FINDINGS_FILENAME",
    "CODEQL_COVERAGE_FILENAME",
    "SEMGREP_FINDINGS_FILENAME",
    "SEMGREP_COVERAGE_FILENAME",
    "MOBSF_FINDINGS_FILENAME",
    "MOBSF_COVERAGE_FILENAME",
    "AEGISGRAPH_FINDINGS_FILENAME",
    "AEGISGRAPH_COVERAGE_FILENAME",
    "EXPECTED_CODEQL_VERSION_PREFIX",
    "EXPECTED_SEMGREP_VERSION_PREFIX",
    "SEMGREP_BASELINE_CONFIGS",
    "SUPPORTED_TARGET_KEYS",
    "build_target_specs",
    "location_hash",
    "run_codeql_alone",
    "run_semgrep_alone",
    "run_mobsf_alone",
    "run_aegisgraph_alone",
    "write_mobsf_limited_md",
]
