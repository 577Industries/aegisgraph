#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$HERE/wrapper.c" ]; then
    echo "wrapper.c missing at $HERE" >&2
    exit 2
fi

CC="${CC:-clang-18}"
if ! command -v "$CC" >/dev/null 2>&1; then
    if command -v cc >/dev/null 2>&1; then
        CC=cc
    else
        echo "SKIP: no C compiler on PATH" >&2
        exit 77
    fi
fi
if ! pkg-config --exists libcurl 2>/dev/null; then
    echo "SKIP: libcurl-dev not installed" >&2
    exit 77
fi

CFLAGS="$(pkg-config --cflags libcurl)"
LDFLAGS="$(pkg-config --libs libcurl)"
(cd "$HERE" && $CC -O2 -Wall -o wrapper wrapper.c $CFLAGS $LDFLAGS)
BIN="$HERE/wrapper"

OUTPUT="$(printf '%s' 'https://example.com/foo' | "$BIN" --input-id SMOKE-007)"

echo "$OUTPUT" | python3 -c "
import json, sys
fv = json.loads(sys.stdin.readline().strip())
assert fv['parser_profile'] == 'libcurl'
assert fv['input_id'] == 'SMOKE-007'
print('libcurl smoke OK')
"
