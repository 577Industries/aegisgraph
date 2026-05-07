# AndroidManifest analyzer (Phase C4)

Pure-Python analyzer for Android `AndroidManifest.xml`. Emits a structured
JSON summary that `extraction/adapters/manifest_to_graph.py` translates into
AegisGraph nodes/edges.

## What it extracts

- `<manifest package="...">`
- `<application android:name="...">`
- `<uses-permission>` and `<permission>` declarations
- `<uses-native-library>` and `<meta-data android:name="android.app.lib_name">`
- Components: `<activity>`, `<activity-alias>`, `<service>`, `<receiver>`,
  `<provider>`
  - `android:exported` (with implicit-true heuristic when an `<intent-filter>`
    is present and `exported` is unset)
  - `android:permission`
  - All child `<intent-filter>` blocks with actions, categories, and full
    `<data>` shape (scheme/host/port/path/pathPrefix/pathPattern/mimeType/ssp)

## Running

```bash
# Clone target source to a temp dir (do NOT commit) and run:
TGT=$(mktemp -d -t signal-XXXXXX)
git clone --depth=1 https://github.com/signalapp/Signal-Android "${TGT}"
( cd "${TGT}" && git checkout 1043851 )

python3 -m extraction.manifest.manifest_analyzer "${TGT}" \
  --output extraction/output/signal/manifest-analysis.json
rm -rf "${TGT}"
```

Output is byte-stable: `sort_keys=True` plus deterministic per-record
sorting. The container `extraction/output/manifest.json` carries the run
timestamp; per-target outputs do not.

## XXE / DTD safety

Targets are *untrusted* third-party source. The analyzer uses
`lxml.etree` with an `XMLParser` configured to disable external entity
resolution, DTD loading, and network access (see `_safe_parser()` in
`manifest_analyzer.py`). The standard-library `xml.etree.ElementTree`
does NOT enforce these defaults (CWE-611). `lxml` is in the project's
pinned dependency set (`pyproject.toml`).

## Graph mapping

The adapter (`extraction/adapters/manifest_to_graph.py`) emits one
`entry_point` node per `(component, intent-filter)` pair, plus one
`control` node per declared `<permission>` and `<uses-native-library>`.
Each node carries:

- `source_anchor = <repo>/tree/<commit>/<relpath>#L<line>` (line is best-
  effort because lxml exposes `.sourceline` on parsed elements; analyzers
  fall back to line 1 if a line is unknown).
- `evidence_source = manifest:<sha256(canonical-component-block)>`

`tool_run_status` for the manifest tool is `"ran"` when at least one
manifest is parsed without errors, `"skipped_pending_target_source"` when
the target tree is not present locally, and `"failed"` when XML parse
errors are raised.
