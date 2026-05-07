#!/usr/bin/env bash
# Smoke test for the python_urllib subprocess wrapper.
#
# Contract:
#   - exits 0 if wrapper produces a single line of valid JSON on stdout
#   - exits non-zero otherwise
# Used by tests/test_polydiff_wrappers_smoke.py and by manual verification.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WRAPPER="$HERE/wrapper.py"

if [ ! -f "$WRAPPER" ]; then
    echo "wrapper.py missing at $WRAPPER" >&2
    exit 2
fi

OUTPUT="$(printf '%s' 'https://example.com/foo' | python3 "$WRAPPER" --input-id SMOKE-001)"

# Validate JSON via python (no jq dependency).
echo "$OUTPUT" | python3 -c "
import json, sys
line = sys.stdin.readline().strip()
fv = json.loads(line)
required = ['input_id', 'parser_profile', 'parsed', 'errors', 'warnings', 'scheme', 'host']
for k in required:
    assert k in fv, f'missing required key: {k}'
assert fv['parser_profile'] == 'python_urllib'
assert fv['input_id'] == 'SMOKE-001'
assert fv['parsed'] is True
assert fv['scheme'] == 'https'
assert fv['host'] == 'example.com'
print('python_urllib smoke OK')
"
