# Parser wrapper: libcurl

| | |
|---|---|
| **Parser** | libcurl `curl_url_*` API |
| **Runtime** | libcurl4 (Debian bookworm) + Clang 18 to build |
| **Source** | https://curl.se/libcurl/c/curl_url.html |
| **Build (host)** | `clang-18 -O2 -o wrapper wrapper.c -lcurl` |
| **Build (Docker)** | `docker build -t polydiff/libcurl .` |
| **Smoke** | `bash test_basic.sh` |

## Why this parser

libcurl's URL API is what most native code paths actually use to talk
to remote services — including everything compiled into Android apps
that link curl, plus a long tail of CLI tools and embedded systems. It
has historically diverged from RFC 3986 in nontrivial ways; see the
curl `curl_url_set` test corpus for canonical disagreements.

## Notes on observability gaps

- `tab_or_newline_stripped`, `control_chars_in_host_rejected` — not
  directly exposed by the C API. Reported as warnings.
- IDN handling depends on whether libcurl was built with `--with-libidn2`.
  We do not try to detect this at runtime; report `host_has_idn` via
  `xn--` prefix sniff only.
