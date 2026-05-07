#!/usr/bin/env bash
# Build a CodeQL Java database for the Signal-Android target at the pin
# defined in aegisgraph/constants.py:TARGETS["signal"].
#
# Reproducible inside the AegisGraph devcontainer (CodeQL CLI 2.20.6 +
# OpenJDK 21 + Gradle from Signal-Android's own gradlew).
#
# Output: extraction/output/signal/codeql-db/  (gitignored)
# Side-effect: target source is cloned to a temp dir and DELETED before exit.
#              This script never commits target source to the AegisGraph repo.
#
# Failure modes:
#   - codeql CLI missing                 -> exits 2
#   - git clone fails (network/refused)  -> exits 3
#   - target commit checkout fails       -> exits 4
#   - codeql db create fails             -> exits 5
set -euo pipefail

# Pinned values mirror aegisgraph/constants.py:TARGETS["signal"]. Bumping the
# pin requires updating BOTH places and re-running extract.
TARGET_NAME="Signal Android"
TARGET_REPO="https://github.com/signalapp/Signal-Android"
TARGET_COMMIT="1043851"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DB_DIR="${REPO_ROOT}/extraction/output/signal/codeql-db"
RAW_DIR="${REPO_ROOT}/extraction/output/signal/raw"

mkdir -p "${RAW_DIR}"

if ! command -v codeql >/dev/null 2>&1; then
  echo "build_db.sh: codeql CLI not found in PATH; cannot build database."
  echo "Install CodeQL CLI (devcontainer pins 2.20.6) and re-run."
  exit 2
fi

CLONE_DIR="$(mktemp -d -t aegisgraph-signal-XXXXXX)"
trap 'rm -rf "${CLONE_DIR}"' EXIT

echo "[1/3] cloning ${TARGET_REPO} -> ${CLONE_DIR}"
git clone --filter=blob:none --no-checkout "${TARGET_REPO}" "${CLONE_DIR}" || exit 3

(
  cd "${CLONE_DIR}"
  echo "[2/3] checking out ${TARGET_COMMIT}"
  git fetch origin "${TARGET_COMMIT}" --depth=1 || true
  git checkout "${TARGET_COMMIT}" || exit 4
)

# Remove any prior DB so codeql create gets a clean target.
rm -rf "${DB_DIR}"
mkdir -p "${DB_DIR}"

echo "[3/3] codeql database create (java) -> ${DB_DIR}"
# Signal-Android uses Gradle; we let CodeQL auto-detect the Java build.
codeql database create "${DB_DIR}" \
  --language=java \
  --source-root="${CLONE_DIR}" \
  --command="${CLONE_DIR}/gradlew :Signal-Android:assembleStagingRelease --no-daemon -x test" \
  >"${RAW_DIR}/codeql-db-create.log" 2>&1 || {
    echo "codeql database create failed; see ${RAW_DIR}/codeql-db-create.log"
    exit 5
  }

echo "build_db.sh OK: ${DB_DIR}"
