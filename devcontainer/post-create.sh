#!/usr/bin/env bash
# AegisGraph Tier 3 research devcontainer post-create.
#
# Runs once at container create. Pins user-space tools that don't fit cleanly
# in the system-wide Dockerfile layer:
#
#   * semgrep 1.86.0 via pipx (kept in the user's pipx home so it can be
#     upgraded without rebuilding the image)
#   * Python project install (`pip install -e .`) for the aegisgraph CLI
#   * Trigger codeql pack download (best-effort; idempotent)
#
# Failures in pipx semgrep install do NOT abort container create — the
# strict-tooling gate (`make tooling-strict`) is the authority on whether the
# environment is usable for reproduce/extract/sanitize. This script's job is
# to install, not to enforce.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${PROJECT_ROOT}"

echo "[post-create] installing aegisgraph python package + dev deps"
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]" || python3 -m pip install -e .
python3 -m pip install pytest jsonschema lxml pyyaml httpx whatwg-url

echo "[post-create] installing semgrep 1.86.0 via pipx"
if ! command -v pipx >/dev/null 2>&1; then
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
    # shellcheck disable=SC1090
    source "${HOME}/.bashrc" || true
fi
# pipx install is idempotent: re-running upgrades or no-ops at the pinned version.
pipx install --force semgrep==1.86.0 || \
    echo "[post-create] WARNING: pipx semgrep install failed; semgrep tooling gate may flag missing"

echo "[post-create] codeql pack pre-fetch (idempotent, best-effort)"
codeql pack download codeql/java-queries codeql/python-queries || \
    echo "[post-create] codeql pack pre-fetch failed; will retry on first scan"

echo "[post-create] writing initial tooling-versions.json"
python3 -m aegisgraph.cli tooling || true

echo "[post-create] done. Run 'make tooling-strict' to verify all required tools."
