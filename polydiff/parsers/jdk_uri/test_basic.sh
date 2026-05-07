#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/Wrapper.java"
CLASS="$HERE/Wrapper.class"

if [ ! -f "$SRC" ]; then
    echo "Wrapper.java missing at $SRC" >&2
    exit 2
fi

if ! command -v javac >/dev/null 2>&1; then
    echo "SKIP: javac not on PATH (env reports JDK absent — JRE only)" >&2
    exit 77
fi
if ! command -v java >/dev/null 2>&1; then
    echo "SKIP: java not on PATH" >&2
    exit 77
fi

if [ ! -f "$CLASS" ] || [ "$SRC" -nt "$CLASS" ]; then
    (cd "$HERE" && javac Wrapper.java)
fi

OUTPUT="$(printf '%s' 'https://example.com/foo' | java -cp "$HERE" Wrapper --input-id SMOKE-003)"

echo "$OUTPUT" | python3 -c "
import json, sys
fv = json.loads(sys.stdin.readline().strip())
assert fv['parser_profile'] == 'jdk_uri'
assert fv['input_id'] == 'SMOKE-003'
assert fv['parsed'] is True
assert fv['scheme'] == 'https'
assert fv['host'] == 'example.com'
print('jdk_uri smoke OK')
"
