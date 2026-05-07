# PolyDiff parser wrappers

Each subdirectory is a subprocess oracle for one URL parser
implementation. Together they replace the three in-process Python
shims (`parse_python_urllib`, `parse_whatwg_like`, `parse_guarded_fetcher`)
that lived in the legacy `aegisgraph/polydiff.py`.

## Contract (per SPEC §5.3)

```
stdin  : up to 64 KiB of UTF-8 (the candidate URL string)
stdout : exactly one JSON object, one line, conforming to v2 fact-vector
         (see polydiff/factvec/schema_v2.json)
exit 0 : parser-or-error verdict (a parse error is part of the fact-vector,
         not a wrapper failure)
exit !=0 : wrapper crash; orchestrator records this as a Finding
```

CLI: `<wrapper> --input-id <ID>`. The orchestrator sets a 100 ms
SIGKILL timeout per input.

## Inventory

| ID | Source | Runtime | Buildable here |
|---|---|---|---|
| `python_urllib` | `urllib.parse` (CPython stdlib) | Python 3.11 | Yes |
| `whatwg_url_py` | `whatwg-url` PyPI package | Python 3.11 + pkg | Yes |
| `jdk_uri` | `java.net.URI` (JDK 21) | OpenJDK 21 | needs javac |
| `okhttp_httpurl` | `okhttp3.HttpUrl` (OkHttp 4.12) | OpenJDK 21 + jar | needs javac+jars |
| `rust_url` | `url` crate (2.5) | Rust 1.79 | needs cargo |
| `go_neturl` | `net/url` (Go 1.22 stdlib) | Go 1.22.5 | needs go |
| `libcurl` | `curl_url_*` API | libcurl4 + clang 18 | needs clang+libcurl-dev |

`PARSER_STATUS.json` records which wrappers are built in the current
environment vs. deferred to the pinned devcontainer.

## Why subprocess and not in-process?

- **Cross-runtime.** No shared Python/JVM/Rust ABI; subprocess is the
  only universal contract.
- **Crash-as-finding.** A parser that segfaults in-process kills the
  orchestrator. As a subprocess, the orchestrator records the crash
  and continues.
- **Time-budget enforcement.** SIGKILL on timeout is the only reliable
  way to bound parse time across language runtimes.
- **No parser library import in the orchestrator.** This is a
  load-bearing safety contract — the orchestrator never trusts a
  parser's library code with its own address space.
