#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WRAPPER="$HERE/wrapper.py"

if [ ! -f "$WRAPPER" ]; then
    echo "wrapper.py missing at $WRAPPER" >&2
    exit 2
fi

OUTPUT="$(printf '%s' 'https://example.com/foo' | python3 "$WRAPPER" --input-id SMOKE-002)"

echo "$OUTPUT" | python3 -c "
import json, sys
fv = json.loads(sys.stdin.readline().strip())
assert fv['parser_profile'] == 'whatwg_url_py'
assert fv['input_id'] == 'SMOKE-002'
assert fv['parsed'] is True or fv['parser_profile'] == 'whatwg_url_py' and fv['errors']
if fv['parsed']:
    assert fv['scheme'] == 'https'
    assert fv['host'] == 'example.com'
print('whatwg_url_py smoke OK')
"
