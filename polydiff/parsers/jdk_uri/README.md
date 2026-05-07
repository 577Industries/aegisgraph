# Parser wrapper: jdk_uri

| | |
|---|---|
| **Parser** | `java.net.URI` from JDK 21 stdlib |
| **Runtime** | OpenJDK 21 (`eclipse-temurin:21.0.5_11-*`) |
| **Source** | https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/URI.html |
| **Build (host)** | `javac Wrapper.java` |
| **Build (Docker)** | `docker build -t polydiff/jdk_uri .` |
| **Smoke** | `bash test_basic.sh` |

## Why this parser

`java.net.URI` follows RFC 2396 (predecessor of RFC 3986). It is the
default URI parser for many Android codepaths and historically diverges
from `okhttp3.HttpUrl` and from WHATWG URL on:

- Whether `https://user@host/` parses as `host=host` vs `host=user@host`
- Case preservation in the host (URI is case-preserving on construction)
- Strict scheme-authority separator handling (`https:foo` is a scheme +
  opaque part, not a host-relative URL)
- Handling of empty userinfo (`https://@evil.com/`)

## Notes on observability gaps

- `host_has_idn`, `host_punycode` — `java.net.URI` does not perform
  IDN conversion. Reported as `null`.
- `tab_or_newline_stripped` — `java.net.URI` rejects most control
  chars via `URISyntaxException` but accepts a subset; reported as
  `null` to be honest.
