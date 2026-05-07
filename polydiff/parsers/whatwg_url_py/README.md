# Parser wrapper: whatwg_url_py

| | |
|---|---|
| **Parser** | [`whatwg-url`](https://pypi.org/project/whatwg-url/) Python package |
| **Runtime** | CPython 3.11 + `whatwg-url==2024.6.0` |
| **Spec** | https://url.spec.whatwg.org |
| **Build** | `docker build -t polydiff/whatwg_url_py .` |
| **Smoke** | `pip install --user whatwg-url && bash test_basic.sh` |
| **Status** | Built locally; replaces the in-process `parse_whatwg_like` shim from the legacy `aegisgraph/polydiff.py` |

## Why this parser

The WHATWG URL Living Standard is what every browser implements. It
diverges from RFC 3986 (which `urllib.parse` follows) on many
security-relevant points:

- Backslashes in special-scheme URLs are converted to forward slashes
- Tabs and newlines are stripped from input
- IDN hostnames are punycode-encoded
- Trailing dots are normalized

When a server-side validator and a browser-side renderer disagree about
URL parsing, you get classic origin-confusion / SSRF bugs.

## Notes on observability gaps

- `tab_or_newline_stripped` is reported as `true` because the spec
  mandates it. The python `whatwg-url` package does not expose a
  before/after view, so we cannot diff to confirm; see the warning.
- `scheme_authority_separator_strict` is reported `null` because
  WHATWG strictness depends on whether a base URL was supplied.
