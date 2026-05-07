#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$HERE/wrapper.go" ]; then
    echo "wrapper.go missing at $HERE" >&2
    exit 2
fi

if ! command -v go >/dev/null 2>&1; then
    echo "SKIP: go not on PATH (Go toolchain absent in current env)" >&2
    exit 77
fi

(cd "$HERE" && go build -o wrapper wrapper.go)
BIN="$HERE/wrapper"

OUTPUT="$(printf '%s' 'https://example.com/foo' | "$BIN" --input-id SMOKE-006)"

echo "$OUTPUT" | python3 -c "
import json, sys
fv = json.loads(sys.stdin.readline().strip())
assert fv['parser_profile'] == 'go_neturl'
assert fv['input_id'] == 'SMOKE-006'
assert fv['parsed'] is True
print('go_neturl smoke OK')
"
