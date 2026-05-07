# Parser wrapper: rust_url

| | |
|---|---|
| **Parser** | [`url`](https://crates.io/crates/url) crate (v2.5.x) |
| **Runtime** | Rust 1.79.0 |
| **Source** | https://github.com/servo/rust-url |
| **Build (host)** | `cargo build --release --bin wrapper` |
| **Build (Docker)** | `docker build -t polydiff/rust_url .` |
| **Smoke** | `bash test_basic.sh` |

## Why this parser

The Rust `url` crate is the WHATWG URL spec implementation used by
Servo, libsignal-rust, and matrix-rust-sdk. It is the closest thing to
a strict-WHATWG reference implementation, distinct from the Python
`whatwg-url` package because the Rust version is the canonical one
relied on by browser/SMA crypto stacks.

## Notes on observability gaps

- IDN is reported as `host_has_idn=true` only when the serialized
  host contains the `xn--` prefix; the crate does the conversion
  silently otherwise.
- `tab_or_newline_stripped`, `backslash_treated_as_slash`,
  `control_chars_in_host_rejected` reported as `true` because the
  WHATWG spec mandates each of these. The crate exposes no
  before/after view.
