# Parser wrapper: python_urllib

| | |
|---|---|
| **Parser** | `urllib.parse.urlsplit` from CPython stdlib |
| **Runtime** | CPython 3.11.10 (devcontainer pin) |
| **Source** | https://docs.python.org/3.11/library/urllib.parse.html |
| **Build** | `docker build -t polydiff/python_urllib .` |
| **Run** | `printf '%s' "https://example.com/" | docker run --rm -i polydiff/python_urllib --input-id ID` |
| **Smoke** | `bash test_basic.sh` |
| **Status** | Built locally; runs without Docker on any host with Python 3.11+ |

## Contract

- stdin: up to 64 KiB UTF-8
- stdout: one JSON line conforming to `polydiff/factvec/schema_v2.json`
  (and also to the proposed `schema/fact-vector.schema.v2.proposed.json`)
- exit 0 on parse-or-error (a parse error is part of the fact-vector)
- exit non-zero only on wrapper crash; the orchestrator treats that as
  a Finding

## Notes on observability gaps

Several v2 axes are not directly observable from `urllib.parse`:

- `host_has_idn`, `host_punycode` — `urllib` does not perform IDN
  conversion. Reported as `null` + warning.
- `control_chars_in_host_rejected` — `urllib` accepts control
  characters in hostnames silently. Reported as `null`.

The disagreement detector treats `null` as "no opinion" and excludes
the axis from comparisons against this parser.
