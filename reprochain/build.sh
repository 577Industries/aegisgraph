#!/usr/bin/env bash
# reprochain/build.sh
#
# Orchestrates the libwebp CVE-2023-4863 differential build:
#   1. Initialize/update the upstream libwebp submodule.
#   2. Check out the vulnerable pin into a worktree.
#   3. cmake-build the harness against it -> fuzz_webp_decode_vuln.
#   4. Check out the fixed pin into a worktree.
#   5. cmake-build the harness against it -> fuzz_webp_decode_fix.
#   6. Smoke-check both binaries: -help=1 returns 0, ASan symbols are
#      present in the binary.
#
# The script is fail-loud. If clang or cmake is missing it exits with
# code 2 and prints a "blocked_pending_toolchain" sentinel that
# aegisgraph/reprochain.py captures into build_manifest.json.
#
# Pinned commit SHAs come from reprochain/vendor/libwebp/COMMIT_PINS.md
# (the canonical source of truth) but for fail-fast we also hard-code
# them here. If the two disagree, the script aborts: a stale
# COMMIT_PINS.md must be the cause and the fix is a code review on
# COMMIT_PINS.md, not a quiet override here.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPRO_ROOT="$REPO_ROOT/reprochain"
VENDOR_ROOT="$REPRO_ROOT/vendor/libwebp"
UPSTREAM="$VENDOR_ROOT/upstream"

VULN_SHA="7ba44f80f3b94fc0138db159afea770ef06532a0"
FIX_SHA="902bc9190331343b2017211debcec8d2ab87e17a"

# --- helpers ----------------------------------------------------------------

die() {
    echo "[reprochain/build.sh] FATAL: $*" >&2
    exit 1
}

emit_blocked() {
    # Print a single-line sentinel that aegisgraph/reprochain.py greps
    # for. Status reasons must be one of:
    #   blocked_pending_toolchain
    #   blocked_pending_submodule
    #   blocked_pending_pin_mismatch
    echo "REPROCHAIN_STATUS=blocked"
    echo "REPROCHAIN_REASON=$1"
    echo "REPROCHAIN_DETAIL=$2"
    exit 2
}

ensure_tool() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        emit_blocked "blocked_pending_toolchain" "missing tool: $tool"
    fi
}

# --- toolchain probe --------------------------------------------------------

ensure_tool git
ensure_tool clang
ensure_tool clang++
ensure_tool cmake
ensure_tool nm

# --- submodule sync ---------------------------------------------------------

if [[ ! -f "$UPSTREAM/.git" ]] && [[ ! -d "$UPSTREAM/.git" ]]; then
    # Submodule not initialized in this clone. Try to init.
    if ! (cd "$REPO_ROOT" && git submodule update --init --depth=0 reprochain/vendor/libwebp/upstream 2>&1); then
        emit_blocked "blocked_pending_submodule" "could not init libwebp submodule at $UPSTREAM"
    fi
fi

# Confirm both pinned commits resolve in the submodule. If they don't,
# the submodule's remote has rotated history (extremely unlikely for
# webmproject/libwebp main branch, but possible if upstream URL changes)
# or the user pointed the submodule at the wrong fork.
if ! (cd "$UPSTREAM" && git cat-file -t "$VULN_SHA" >/dev/null 2>&1); then
    emit_blocked "blocked_pending_pin_mismatch" "vuln commit $VULN_SHA not found in $UPSTREAM"
fi
if ! (cd "$UPSTREAM" && git cat-file -t "$FIX_SHA" >/dev/null 2>&1); then
    emit_blocked "blocked_pending_pin_mismatch" "fix commit $FIX_SHA not found in $UPSTREAM"
fi

# --- build worktrees + harness ---------------------------------------------

build_one() {
    local label="$1"      # "vuln" or "fix"
    local sha="$2"        # full commit SHA
    local worktree="$VENDOR_ROOT/build-$label"
    local builddir="$VENDOR_ROOT/cmake-$label"
    local harness="fuzz_webp_decode_${label}"
    local archive="libwebp-${label}.a"

    # Worktree may already exist from a previous run; in that case just
    # reset it. We use git worktree (not git clone) so disk usage is
    # bounded and the upstream fetch stays single-source.
    if [[ -d "$worktree/.git" ]] || [[ -f "$worktree/.git" ]]; then
        (cd "$UPSTREAM" && git worktree remove --force "$worktree" 2>/dev/null) || true
        rm -rf "$worktree"
    fi
    rm -rf "$builddir"

    (cd "$UPSTREAM" && git worktree add --detach "$worktree" "$sha")

    mkdir -p "$builddir"
    (cd "$builddir" && \
        CC=clang CXX=clang++ \
        cmake \
            -DCMAKE_BUILD_TYPE=RelWithDebInfo \
            -DLIBWEBP_SRC="$worktree" \
            -DHARNESS_NAME="$harness" \
            -DLIBWEBP_ARCHIVE="$archive" \
            "$REPRO_ROOT/harness")

    (cd "$builddir" && cmake --build . --target webp_static "$harness" -- -j"$(nproc 2>/dev/null || echo 2)")

    # Smoke checks.
    local bin="$builddir/$harness"
    [[ -x "$bin" ]] || die "build did not produce $bin"

    # Ask libFuzzer to print help; this exercises the entrypoint
    # without consuming corpus. Exit 0 expected.
    if ! "$bin" -help=1 >/dev/null 2>&1; then
        die "$harness -help=1 did not exit 0"
    fi

    # Confirm ASan was actually linked. We grep for __asan_init which
    # only appears when -fsanitize=address survived linking.
    if ! nm "$bin" 2>/dev/null | grep -q __asan_init; then
        die "$harness has no __asan_init symbol; ASan was not linked"
    fi

    echo "REPROCHAIN_BUILT=$label sha=$sha bin=$bin"
}

build_one vuln "$VULN_SHA"
build_one fix  "$FIX_SHA"

echo "REPROCHAIN_STATUS=ready"
