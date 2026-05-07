#!/usr/bin/env bash
# Run all eight AegisGraph SMA queries against an existing CodeQL DB and emit
# one merged SARIF file per target. Adapter
# extraction/adapters/codeql_to_graph.py consumes that SARIF.
#
# Usage:
#   run_queries.sh <target-key>          # target-key in {signal, element-x}
#
# Inputs:
#   extraction/output/<target>/codeql-db   (built by extraction/targets/<target>/build_db.sh)
# Outputs (gitignored):
#   extraction/output/<target>/raw/codeql-merged.sarif
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <signal|element-x>"
  exit 1
fi

TARGET_KEY="$1"
case "${TARGET_KEY}" in
  signal|element-x) ;;
  *) echo "unknown target: ${TARGET_KEY}"; exit 1 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DB_DIR="${REPO_ROOT}/extraction/output/${TARGET_KEY}/codeql-db"
QL_DIR="${REPO_ROOT}/extraction/codeql"
SARIF_OUT="${REPO_ROOT}/extraction/output/${TARGET_KEY}/raw/codeql-merged.sarif"

if ! command -v codeql >/dev/null 2>&1; then
  echo "codeql CLI not in PATH; run inside the devcontainer."
  exit 2
fi

if [[ ! -d "${DB_DIR}" ]]; then
  echo "DB missing at ${DB_DIR}. Run extraction/targets/${TARGET_KEY}-android/build_db.sh first."
  exit 3
fi

mkdir -p "$(dirname "${SARIF_OUT}")"

# `codeql database analyze --format=sarifv2.1.0` runs every query in the
# pack's defaultSuiteFile and emits a single SARIF document with one Run
# entry per query. The adapter then keys results by rule.id.
codeql database analyze \
  "${DB_DIR}" \
  "${QL_DIR}" \
  --format=sarifv2.1.0 \
  --output="${SARIF_OUT}" \
  --threads=0

echo "wrote ${SARIF_OUT}"
