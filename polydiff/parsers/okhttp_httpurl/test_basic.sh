#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/Wrapper.java"

if [ ! -f "$SRC" ]; then
    echo "Wrapper.java missing at $SRC" >&2
    exit 2
fi

# This wrapper requires javac + okhttp + okio jars on the classpath.
# Without those (current dev environment), the smoke test reports SKIP (77).
if ! command -v javac >/dev/null 2>&1; then
    echo "SKIP: javac not on PATH" >&2
    exit 77
fi

if [ -z "${OKHTTP_JAR:-}" ] || [ -z "${OKIO_JAR:-}" ]; then
    echo "SKIP: OKHTTP_JAR and OKIO_JAR env vars not set" >&2
    echo "  set them to the okhttp + okio jars (see Dockerfile for canonical versions)" >&2
    exit 77
fi

CP="$HERE:$OKHTTP_JAR:$OKIO_JAR${KOTLIN_JAR:+:$KOTLIN_JAR}"
(cd "$HERE" && javac -cp "$CP" Wrapper.java)

OUTPUT="$(printf '%s' 'https://example.com/foo' | java -cp "$CP" Wrapper --input-id SMOKE-004)"

echo "$OUTPUT" | python3 -c "
import json, sys
fv = json.loads(sys.stdin.readline().strip())
assert fv['parser_profile'] == 'okhttp_httpurl'
assert fv['input_id'] == 'SMOKE-004'
print('okhttp_httpurl smoke OK')
"
