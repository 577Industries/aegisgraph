#!/usr/bin/env bash
# Build a CodeQL Java database for the Element-X-Android target at the pin
# defined in aegisgraph/constants.py:TARGETS["element-x"].
#
# Reproducible inside the AegisGraph devcontainer.
#
# Output: extraction/output/element-x/codeql-db/  (gitignored)
# Side-effect: target source cloned to a temp dir and DELETED before exit.
#
# Element X uses MatrixRustSDK bindings (Rust compiled to JNI). The CodeQL
# Java DB captures only the Kotlin/Java side of the bridge; the Rust side is
# tracked via reprochain (see reprochain/vendor/libwebp/README.md for the
# Rust pin pattern).
set -euo pipefail

TARGET_NAME="Element X Android"
TARGET_REPO="https://github.com/element-hq/element-x-android"
TARGET_COMMIT="91d265e6"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DB_DIR="${REPO_ROOT}/extraction/output/element-x/codeql-db"
RAW_DIR="${REPO_ROOT}/extraction/output/element-x/raw"

mkdir -p "${RAW_DIR}"

if ! command -v codeql >/dev/null 2>&1; then
  echo "build_db.sh: codeql CLI not found in PATH; cannot build database."
  echo "Install CodeQL CLI (devcontainer pins 2.20.6) and re-run."
  exit 2
fi

CLONE_DIR="$(mktemp -d -t aegisgraph-elementx-XXXXXX)"
trap 'rm -rf "${CLONE_DIR}"' EXIT

echo "[1/3] cloning ${TARGET_REPO} -> ${CLONE_DIR}"
git clone --filter=blob:none --no-checkout "${TARGET_REPO}" "${CLONE_DIR}" || exit 3

(
  cd "${CLONE_DIR}"
  echo "[2/3] checking out ${TARGET_COMMIT}"
  git fetch origin "${TARGET_COMMIT}" --depth=1 || true
  git checkout "${TARGET_COMMIT}" || exit 4
)

rm -rf "${DB_DIR}"
mkdir -p "${DB_DIR}"

echo "[3/3] codeql database create (java) -> ${DB_DIR}"
codeql database create "${DB_DIR}" \
  --language=java \
  --source-root="${CLONE_DIR}" \
  --command="${CLONE_DIR}/gradlew assembleRelease --no-daemon -x test" \
  >"${RAW_DIR}/codeql-db-create.log" 2>&1 || {
    echo "codeql database create failed; see ${RAW_DIR}/codeql-db-create.log"
    exit 5
  }

echo "build_db.sh OK: ${DB_DIR}"
