#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$HERE/wrapper.rs" ]; then
    echo "wrapper.rs missing at $HERE" >&2
    exit 2
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo not on PATH (Rust toolchain absent in current env)" >&2
    exit 77
fi

(cd "$HERE" && cargo build --release --bin wrapper)
BIN="$HERE/target/release/wrapper"
if [ ! -x "$BIN" ]; then
    echo "build did not produce $BIN" >&2
    exit 2
fi

OUTPUT="$(printf '%s' 'https://example.com/foo' | "$BIN" --input-id SMOKE-005)"

echo "$OUTPUT" | python3 -c "
import json, sys
fv = json.loads(sys.stdin.readline().strip())
assert fv['parser_profile'] == 'rust_url'
assert fv['input_id'] == 'SMOKE-005'
assert fv['parsed'] is True
print('rust_url smoke OK')
"
