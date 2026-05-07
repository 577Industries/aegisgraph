# Parser wrapper: okhttp_httpurl

| | |
|---|---|
| **Parser** | `okhttp3.HttpUrl` (OkHttp 4.12.0) |
| **Runtime** | OpenJDK 21 + OkHttp 4.12.0 + okio 3.6.0 |
| **Source** | https://github.com/square/okhttp/blob/parent-4.12.0/okhttp/src/main/kotlin/okhttp3/HttpUrl.kt |
| **Build (Docker)** | `docker build -t polydiff/okhttp_httpurl .` |
| **Smoke** | `OKHTTP_JAR=/path/okhttp.jar OKIO_JAR=/path/okio.jar bash test_basic.sh` |

## Why this parser

`okhttp3.HttpUrl` is the URL parser used by OkHttp, which is the
networking library underneath Signal Android, Element X Android, and
most modern Android apps. It is more permissive than `java.net.URI`
on:

- Userinfo with empty username (`https://@evil.com/`)
- Trailing dots in hosts
- Whitespace in input (it will trim some, reject others)
- Idn handling — okhttp performs IDN normalization

OkHttp's permissiveness vs `java.net.URI`'s strictness is one of the
classic origin-confusion footguns documented in Snyk's 2022 URL-parser
study and in the Bishop Fox writeups.

## Notes on observability gaps

- `tab_or_newline_stripped` reported `false` because okhttp rejects
  most control chars rather than stripping them. That said, the precise
  set is version-dependent; see the Snyk 2022 corpus for variations.
- `path_traversal_resolved` reported `true` because okhttp resolves
  `..` segments per RFC 3986 §5.2.4.
