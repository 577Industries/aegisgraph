# AegisGraph Semgrep rules

Four rules cover SMA misconfiguration patterns that complement the CodeQL
queries by catching cases that don't require a working DB build. Each
rule's `metadata.aegisgraph_path_class` tag is consumed by
`extraction/adapters/semgrep_to_graph.py`.

| Rule | path_class | node_type |
|---|---|---|
| `webview-misconfig.yml` | `link_preview` | `parser` |
| `unsafe-deeplink-handler.yml` | `deeplink` | `handler` |
| `tainted-jni-bridge.yml` | `native_boundary` | `native_boundary` |
| `permissive-intent-filter.yml` | `deeplink` | `entry_point` |

## Running

```bash
# Clone target source to a temp dir (DO NOT commit), then run rules:
TGT=$(mktemp -d -t signal-XXXXXX)
git clone --depth=1 https://github.com/signalapp/Signal-Android "${TGT}"
( cd "${TGT}" && git checkout 1043851 )

semgrep --config extraction/semgrep/rules/ \
  --json --output extraction/output/signal/raw/semgrep.json \
  "${TGT}"

# Adapter normalizes the JSON into AegisGraph nodes.
python3 -m extraction.adapters.semgrep_to_graph signal
```

The adapter requires the env var `AEGISGRAPH_TARGET_SOURCE_ROOT` to point
at the cloned source root, so that `source_anchor` URLs can be relative
to the pinned commit instead of absolute filesystem paths.

When semgrep is unavailable the rules ship as source-of-truth and the
adapter records `tool_run_status="skipped_pending_toolchain"` for
semgrep — see `extraction/BUILD_STATUS.md`.
