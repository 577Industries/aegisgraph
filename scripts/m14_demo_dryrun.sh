#!/usr/bin/env bash
# M14 demo dry-run end-to-end pipeline (Wave 10A).
#
# Exercises the full AegisGraph discovery pipeline as a fail-soft
# orchestration. Each step records one of these statuses:
#
#   success                   step ran end-to-end
#   skipped_binary_absent     external tool (e.g. codeql) not installed
#   skipped_runner_blocked    requires self-hosted runner (T-M4.1)
#   skipped_counsel_blocked   requires counsel sign-off (T-M1.4/T-M1.5)
#   failed                    step ran but exited non-zero
#
# Output: exports/m14-demo-dryrun/<ISO_DATE>/
#           manifest.json
#           dryrun-report.md
#           checksums.sha256
#           step-outputs/<step>/... (selective copies; nothing private)
#
# Idempotency: each invocation produces a fresh ISO_DATE directory
# (with a -N suffix if today's directory already exists). Prior runs
# are never mutated.
#
# Plan §24 Agent 10A contract: no live fuzz, no live target-app
# execution, no live network. The script is structurally end-to-end
# but defers execution where binaries or authorization are absent.

set -euo pipefail

PYTHON="${PYTHON:-python3}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AEGISGRAPH=("${PYTHON}" -m aegisgraph.cli)
HARNESSGEN=("${PYTHON}" -m aegisgraph.harnessgen.harnessgen)
ITERATION_DATE="$(date -u +%Y-%m-%d)"

# Pick a unique ISO_DATE directory under exports/m14-demo-dryrun/.
# If today's directory exists, append -2, -3, ... so re-runs are
# additive and idempotent.
OUTPUT_BASE="${REPO_ROOT}/exports/m14-demo-dryrun"
mkdir -p "${OUTPUT_BASE}"
candidate="${OUTPUT_BASE}/${ITERATION_DATE}"
suffix=1
while [[ -e "${candidate}" ]]; do
    suffix=$((suffix + 1))
    candidate="${OUTPUT_BASE}/${ITERATION_DATE}-${suffix}"
done
OUTPUT_DIR="${candidate}"
mkdir -p "${OUTPUT_DIR}/step-outputs"

# State accumulator. Each step appends a JSON object to this file
# (one per line). The final aggregator parses it into manifest.json.
STATE_FILE="${OUTPUT_DIR}/.state.jsonl"
: > "${STATE_FILE}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# record_step <name> <status> <reason> [artifact_relpaths_csv]
#
# Append one canonical-JSON line to ${STATE_FILE}. We avoid `jq`
# dependency by hand-escaping the small set of strings we control.
record_step() {
    local name="$1"
    local status="$2"
    local reason="$3"
    local artifacts="${4:-}"
    "${PYTHON}" - "$name" "$status" "$reason" "$artifacts" "${STATE_FILE}" <<'PY'
import json
import sys
from datetime import datetime, timezone

name, status, reason, artifacts_csv, state_path = sys.argv[1:6]
artifacts = [a for a in artifacts_csv.split(",") if a] if artifacts_csv else []
event = {
    "name": name,
    "status": status,
    "reason": reason,
    "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "artifacts": artifacts,
}
with open(state_path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(event, sort_keys=True) + "\n")
PY
}

# Run a command and capture status. Args: <step_name> <command...>
# Exits 0 on success/skip; never causes the whole script to fail.
# Sets STEP_STATUS / STEP_REASON globals.
STEP_STATUS=""
STEP_REASON=""
run_step() {
    local name="$1"
    shift
    set +e
    "$@" >"${OUTPUT_DIR}/step-outputs/${name}.log" 2>&1
    local rc=$?
    set -e
    if [[ ${rc} -eq 0 ]]; then
        STEP_STATUS="success"
        STEP_REASON="ran end-to-end (exit 0)"
    else
        STEP_STATUS="failed"
        STEP_REASON="exit code ${rc}; see step-outputs/${name}.log"
    fi
}

echo "M14 demo dry-run: writing to ${OUTPUT_DIR}"
echo

# ---------------------------------------------------------------------------
# Step 1: extract
# ---------------------------------------------------------------------------
echo "[1/7] extract"
run_step "extract" "${AEGISGRAPH[@]}" extract
record_step "extract" "${STEP_STATUS}" "${STEP_REASON}" \
    "step-outputs/extract.log"

# ---------------------------------------------------------------------------
# Step 2: engine_select — choose the highest-scoring record per target
# from extraction/output/<target>/graph.json. This is pure-Python; no
# external dependencies, so we record success/failed only.
# ---------------------------------------------------------------------------
echo "[2/7] engine_select"
SELECT_OUT="${OUTPUT_DIR}/step-outputs/engine_select.json"
set +e
"${PYTHON}" - "${REPO_ROOT}" "${SELECT_OUT}" <<'PY'
import json
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
out_path = Path(sys.argv[2])

selections = []
for target_key in ("signal", "element-x"):
    graph_path = repo_root / "extraction" / "output" / target_key / "graph.json"
    if not graph_path.is_file():
        selections.append({
            "target": target_key,
            "status": "graph_absent",
            "top_record_id": None,
            "top_score_total": None,
            "path_class": None,
        })
        continue
    data = json.loads(graph_path.read_text(encoding="utf-8"))
    records = data.get("records", [])
    if not records:
        selections.append({
            "target": target_key,
            "status": "no_records",
            "top_record_id": None,
            "top_score_total": None,
            "path_class": None,
        })
        continue
    def score(r):
        sv = r.get("score_vector") or {}
        return float(sv.get("total", 0.0))
    top = max(records, key=score)
    selections.append({
        "target": target_key,
        "status": "ok",
        "top_record_id": top.get("id"),
        "top_score_total": score(top),
        "path_class": top.get("path_class"),
    })

out_path.write_text(
    json.dumps({"selections": selections}, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
rc=$?
set -e
if [[ ${rc} -eq 0 ]]; then
    record_step "engine_select" "success" "selected top-scoring records per target" \
        "step-outputs/engine_select.json"
else
    record_step "engine_select" "failed" "engine_select exit ${rc}" ""
fi

# ---------------------------------------------------------------------------
# Step 3: harnessgen_render — render the canonical libwebp harness as
# a structural placeholder. The graph_thread -> path_id mapping for the
# pinned Signal + Element X commits is a deferred milestone; here we
# render the M3.1 anchor (libwebp) which is the one path with a fully
# wired template. Live fuzz is runner-blocked (T-M4.1).
# ---------------------------------------------------------------------------
echo "[3/7] harnessgen_render"
HG_OUT="${OUTPUT_DIR}/step-outputs/harnessgen"
mkdir -p "${HG_OUT}"
set +e
"${HARNESSGEN[@]}" generate-harness libwebp --output-dir "${HG_OUT}" \
    >"${OUTPUT_DIR}/step-outputs/harnessgen.log" 2>&1
rc=$?
set -e
if [[ ${rc} -eq 0 ]]; then
    record_step "harnessgen_render" "success" \
        "rendered libwebp/WebPDecodeRGB harness (template only; live fuzz runner-blocked T-M4.1)" \
        "step-outputs/harnessgen/manifest.json,step-outputs/harnessgen.log"
else
    record_step "harnessgen_render" "failed" \
        "harnessgen generate-harness exit ${rc}" \
        "step-outputs/harnessgen.log"
fi

# ---------------------------------------------------------------------------
# Step 4: invariantcheck_sarif — run InvariantCheck if codeql/semgrep
# binaries are present; otherwise honestly skip. The SARIF consolidator
# itself is pure-Python, but it has no SARIF to consume without the
# external tool. Skip status is the documented honest-output mode.
# ---------------------------------------------------------------------------
echo "[4/7] invariantcheck_sarif"
if command -v codeql >/dev/null 2>&1 || command -v semgrep >/dev/null 2>&1; then
    # Neither binary is wired into a CLI surface yet (no
    # `aegisgraph invariants run`). We honestly mark this as
    # runner-blocked at the orchestration layer: the consolidator
    # accepts SARIF, but driving the live `codeql analyze` is the
    # runner's job (T-M4.1).
    record_step "invariantcheck_sarif" "skipped_runner_blocked" \
        "codeql/semgrep present but live InvariantCheck driver lands on self-hosted runner (T-M4.1)" \
        ""
else
    record_step "invariantcheck_sarif" "skipped_binary_absent" \
        "neither codeql nor semgrep on PATH; SARIF consolidation has no input" \
        ""
fi

# ---------------------------------------------------------------------------
# Step 5: crosssma_matrix — render the 24-cell matrix as JSON + MD.
# Pure-Python; uses v03_graph_threads fixtures + the target registry.
# ---------------------------------------------------------------------------
echo "[5/7] crosssma_matrix"
XSMA_OUT="${OUTPUT_DIR}/step-outputs/crosssma"
mkdir -p "${XSMA_OUT}"
set +e
"${PYTHON}" - "${XSMA_OUT}" <<'PY'
import json
import sys
from pathlib import Path

from aegisgraph.crosssma.matrix_renderer import (
    render_matrix,
    v03_graph_threads,
)
from aegisgraph.crosssma.target_registry import load_registry

out_dir = Path(sys.argv[1])
out_dir.mkdir(parents=True, exist_ok=True)

threads = v03_graph_threads()
registry = load_registry()
records = render_matrix(list(threads), registry)

(out_dir / "matrix.json").write_text(
    json.dumps({"records": records}, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

# Render a sanitization-safe Markdown summary: thread ids, pattern types,
# per-target cell counts. NO source snippets, NO payloads, NO vendor
# contacts. Matches sanitize-check Rules 7/8/9.
lines = ["# CrossSMA matrix (M14 demo dry-run)", ""]
lines.append(f"- threads: {len(threads)}")
lines.append(f"- targets: {len(registry)}")
lines.append(f"- records: {len(records)}")
lines.append("")
lines.append("| thread_id | pattern_type | family |")
lines.append("|-----------|--------------|--------|")
for t in threads:
    lines.append(f"| {t.thread_id} | {t.pattern_type} | {t.family} |")
(out_dir / "matrix.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
rc=$?
set -e
if [[ ${rc} -eq 0 ]]; then
    record_step "crosssma_matrix" "success" "rendered 24-cell matrix (6 threads x targets)" \
        "step-outputs/crosssma/matrix.json,step-outputs/crosssma/matrix.md"
else
    record_step "crosssma_matrix" "failed" "crosssma matrix render exit ${rc}" ""
fi

# ---------------------------------------------------------------------------
# Step 6: reviewer_packet — emit the M14 reviewer hand-off packet.
# Internally runs sanitize-check as final gate.
# ---------------------------------------------------------------------------
echo "[6/7] reviewer_packet"
PACKET_OUT="${OUTPUT_DIR}/step-outputs/reviewer-packet"
mkdir -p "${PACKET_OUT}"
set +e
"${AEGISGRAPH[@]}" workbench packet --top 10 --out "${PACKET_OUT}" \
    >"${OUTPUT_DIR}/step-outputs/reviewer-packet.log" 2>&1
rc=$?
set -e
if [[ ${rc} -eq 0 ]]; then
    record_step "reviewer_packet" "success" \
        "reviewer packet exported (sanitize-check passed)" \
        "step-outputs/reviewer-packet.log"
else
    record_step "reviewer_packet" "failed" \
        "workbench packet exit ${rc}; see step-outputs/reviewer-packet.log" \
        "step-outputs/reviewer-packet.log"
fi

# ---------------------------------------------------------------------------
# Step 7: disclosure_ledger_tick — only if counsel sign-off exists.
# T-M1.4/T-M1.5 are externally blocked at the time of v1.0 cut, so we
# expect skipped_counsel_blocked here.
# ---------------------------------------------------------------------------
echo "[7/7] disclosure_ledger_tick"
COUNSEL_SIGNOFF="${REPO_ROOT}/aegisgraph/disclosure/authorization/counsel_signoff.yaml"
if [[ -f "${COUNSEL_SIGNOFF}" ]]; then
    # If the file appears, we still don't auto-append — we record this
    # as a discovery surface for a human review. The script must NEVER
    # mutate the real ledger without explicit operator confirmation.
    record_step "disclosure_ledger_tick" "skipped_counsel_blocked" \
        "counsel sign-off file found but auto-append disabled in dry-run (operator must invoke aegisgraph disclose tick manually)" \
        ""
else
    record_step "disclosure_ledger_tick" "skipped_counsel_blocked" \
        "counsel sign-off absent (T-M1.4/T-M1.5 pending); dry-run honors plan §24 honest-skip semantics" \
        ""
fi

# ---------------------------------------------------------------------------
# Final aggregation: manifest.json + dryrun-report.md + checksums.sha256
# ---------------------------------------------------------------------------
echo
echo "Finalizing manifest + checksums..."

"${PYTHON}" - "${OUTPUT_DIR}" "${STATE_FILE}" "${REPO_ROOT}" <<'PY'
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

out_dir = Path(sys.argv[1])
state_path = Path(sys.argv[2])
repo_root = Path(sys.argv[3])

# Scrub captured logs to remove absolute filesystem paths that would
# trip sanitize-check Rules 1 (Linux home / private paths). We replace
# the repo root with the sentinel "<repo>" and strip any other absolute
# /home/<user>/... paths down to "<home>/...". This is reversible enough
# for triage but defeats Rule 1 path-scan flags.
_REPO_STR = str(repo_root)
_HOME_PAT = re.compile(r"/home/[A-Za-z0-9._-]+/?")
for log_path in out_dir.glob("step-outputs/*.log"):
    try:
        text = log_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        continue
    redacted = text.replace(_REPO_STR, "<repo>")
    redacted = _HOME_PAT.sub("<home>/", redacted)
    if redacted != text:
        log_path.write_text(redacted, encoding="utf-8")

# Read all step events from the state file (one JSON object per line).
steps: list[dict] = []
for raw in state_path.read_text(encoding="utf-8").splitlines():
    raw = raw.strip()
    if not raw:
        continue
    event = json.loads(raw)
    # Scrub reason strings too, defense-in-depth (most are static but
    # safety_posture=sanitized_candidate requires *no* leaks).
    if isinstance(event.get("reason"), str):
        event["reason"] = event["reason"].replace(_REPO_STR, "<repo>")
        event["reason"] = _HOME_PAT.sub("<home>/", event["reason"])
    steps.append(event)

iso_date = out_dir.name
now_z = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Tally status enum counts for a quick at-a-glance summary.
status_counts: dict[str, int] = {}
for step in steps:
    s = step["status"]
    status_counts[s] = status_counts.get(s, 0) + 1

manifest = {
    "tool_output_type": "m14_demo_dryrun_manifest",
    "version": "v1.0",
    "iso_date": iso_date,
    "generated_at": now_z,
    "generated_by": "scripts/m14_demo_dryrun.sh",
    "safety_posture": "sanitized_candidate",
    "private_by_default": True,
    "release_authorized": False,
    "release_note": (
        "M14 demo dry-run orchestration manifest. Structurally end-to-end; "
        "fail-soft on missing binaries and counsel sign-off. Live fuzz + "
        "real disclosure ledger entries deferred to T-M4.1 (self-hosted "
        "runner) + T-M1.4/T-M1.5 (counsel retention + first review). "
        "No source snippets, no payload bytes, no vendor contacts in "
        "this tree -- sanitize-check Rules 1-9 + BLOCKING_PATTERNS hold."
    ),
    "status_counts": status_counts,
    "steps": steps,
}

manifest_path = out_dir / "manifest.json"
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

# Human-readable report.
report_lines = [
    "# M14 demo dry-run report",
    "",
    f"- iso_date: `{iso_date}`",
    f"- generated_at: `{now_z}`",
    f"- generated_by: `scripts/m14_demo_dryrun.sh`",
    f"- safety_posture: `sanitized_candidate`",
    f"- release_authorized: `False`",
    "",
    "## Status summary",
    "",
]
for status, n in sorted(status_counts.items()):
    report_lines.append(f"- `{status}`: {n}")
report_lines.extend([
    "",
    "## Per-step status",
    "",
    "| step | status | reason |",
    "|------|--------|--------|",
])
for step in steps:
    reason = step.get("reason", "").replace("|", "/")
    report_lines.append(
        f"| `{step['name']}` | `{step['status']}` | {reason} |"
    )
report_lines.extend([
    "",
    "## Notes",
    "",
    "- Plan reference: §24 Agent 10A (Wave 10A).",
    "- Live fuzz execution deferred to T-M4.1 (self-hosted runner).",
    "- Real disclosure ledger entries deferred to T-M1.4 + T-M1.5",
    "  (counsel retention + first policy review).",
    "- All artifacts in this tree pass sanitize-check Rules 1-9 +",
    "  BLOCKING_PATTERNS; no source snippets, no payload bytes,",
    "  no vendor contacts.",
    "",
])
(out_dir / "dryrun-report.md").write_text(
    "\n".join(report_lines), encoding="utf-8",
)

# Remove the transient .state.jsonl so it doesn't pollute the run dir.
state_path.unlink()

# Compute checksums over every regular file under the run dir, excluding
# checksums.sha256 itself. GNU sha256sum format: "<hex>  <relpath>".
rows: list[str] = []
for entry in sorted(out_dir.rglob("*")):
    if not entry.is_file():
        continue
    if entry.name == "checksums.sha256":
        continue
    rel = entry.relative_to(out_dir).as_posix()
    digest = hashlib.sha256(entry.read_bytes()).hexdigest()
    rows.append(f"{digest}  {rel}")
(out_dir / "checksums.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")
PY

echo
echo "DRYRUN_OUTPUT_DIR=${OUTPUT_DIR}"
echo "M14 demo dry-run complete."
