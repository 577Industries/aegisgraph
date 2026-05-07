"""AegisGraph extraction adapters (Phase C5).

Each adapter takes raw tool output (SARIF, semgrep JSON, manifest JSON, MobSF
JSON) plus target metadata and emits a homogeneous AdapterResult shape:

    {
        "tool": "codeql" | "semgrep" | "manifest" | "mobsf",
        "tool_run_status": {
            "status": "ran" | "skipped" | "failed",
            "reason": str | None,
            "tool_output_hash": str | None,  # sha256 hex of the raw output bytes
        },
        "nodes": [<node>, ...],     # AegisGraph node objects
        "edges": [<edge>, ...],     # AegisGraph edge objects (within-tool only)
        "node_index": {<id>: <node>},
    }

assemble.py merges per-tool AdapterResults into one evidence record per
path_class.
"""

from __future__ import annotations
