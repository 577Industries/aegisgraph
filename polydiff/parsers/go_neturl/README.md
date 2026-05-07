# Parser wrapper: go_neturl

| | |
|---|---|
| **Parser** | `net/url` from Go 1.22 stdlib |
| **Runtime** | Go 1.22.5 |
| **Source** | https://pkg.go.dev/net/url |
| **Build (host)** | `go build -o wrapper wrapper.go` |
| **Build (Docker)** | `docker build -t polydiff/go_neturl .` |
| **Smoke** | `bash test_basic.sh` |

## Why this parser

Go's `net/url` follows RFC 3986. It is used as a third reference
implementation in the regression set. Differs from `urllib.parse` and
`java.net.URI` notably on:

- Percent-decoding behavior in `Path` (returned decoded; `RawPath`
  preserved) vs. RFC ambiguity
- Acceptance of `//` ambiguities in scheme-relative paths
- Treatment of trailing-dot hostnames

## Notes on observability gaps

- IDN handling is not built into `net/url`; reported via `xn--`
  prefix sniff.
- `control_chars_in_host_rejected` reported `null`; Go accepts most
  control chars silently.
