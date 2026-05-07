# AegisGraph SMA CodeQL queries

Eight queries cover the SMA path-classes that AegisGraph Tier 3 anchors.
Pack metadata is in `../qlpack.yml`; run-all suite is `aegisgraph-sma.qls`.

| Query | Path-class | Output node-type |
|---|---|---|
| `entry-point-intent.ql` | `inbound_message`, `deeplink` | `entry_point` |
| `inbound-message-handler.ql` | `inbound_message` | `handler` |
| `link-preview-fetch.ql` | `link_preview` | `parser` |
| `qr-handler.ql` | `qr_device_link` | `handler` |
| `media-decoder-entry.ql` | `media_decode` | `decoder` |
| `native-method-with-tainted-input.ql` | `native_boundary` | `native_boundary` |
| `device-linking-flow.ql` | `qr_device_link`, `sync_state` | `control` |
| `key-storage-access.ql` | `crypto_key_lifecycle` | `control` |

## Running

```bash
# Build CodeQL DB once per target (long; uses Gradle).
extraction/targets/signal-android/build_db.sh
extraction/targets/element-x-android/build_db.sh

# Run all queries against a DB and emit a merged SARIF.
extraction/codeql/run_queries.sh signal
extraction/codeql/run_queries.sh element-x

# Adapter normalizes SARIF -> AegisGraph nodes/edges.
python3 -m extraction.adapters.codeql_to_graph signal
```

The SARIF output is gitignored (`extraction/output/<target>/raw/`). Only
the normalized graph (`extraction/output/<target>/graph.json`) and
coverage (`extraction/output/<target>/coverage.json`) are committed.

## Reproducibility

CodeQL CLI is pinned in `devcontainer/Dockerfile` (2.20.6). When the
host environment lacks CodeQL, the queries still ship as source-of-truth
and the extraction adapter records `tool_run_status="skipped_pending_toolchain"`
for the codeql tool — see `extraction/BUILD_STATUS.md`.

Each query annotation block is the documentation contract: ID, kind, and
tags. The `aegisgraph-sma` tag groups the suite for SARIF post-processing.
