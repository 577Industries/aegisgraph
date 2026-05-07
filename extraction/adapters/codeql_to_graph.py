"""SARIF -> AegisGraph adapter for the AegisGraph SMA CodeQL queries.

Each SARIF result becomes a node:
  - `id = "codeql.<query-suffix>.<sha256[:12]>"` (deterministic across runs)
  - `node_type` is mapped from query id -> node-type table.
  - `source_anchor = <repo>/tree/<commit>/<rel-path>#L<line>`
  - `evidence_source = "<query-id>:<sarif-output-hash>"` (the sarif hash is
    the bytes-hash of the merged SARIF document, so anyone re-running the
    pipeline can verify the same evidence corresponds to the same scanner
    output).

When SARIF is missing (toolchain absent, DB build skipped), the adapter
emits a `status="skipped_pending_toolchain"` AdapterResult with zero
nodes/edges.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ._common import (
    PATH_CLASSES,
    adapter_result,
    github_anchor,
    relative_source_path,
    sha256_file,
    sha256_text,
    stable_node_id,
    truncate,
)


# Map from CodeQL rule.id -> (node_type, path_class). Rule IDs are emitted by
# the @id annotation in each .ql file (see extraction/codeql/queries/*.ql).
QUERY_NODE_MAP: dict[str, tuple[str, str]] = {
    "aegisgraph/entry-point-intent": ("entry_point", "deeplink"),
    "aegisgraph/inbound-message-handler": ("handler", "inbound_message"),
    "aegisgraph/link-preview-fetch": ("parser", "link_preview"),
    "aegisgraph/qr-handler": ("handler", "qr_device_link"),
    "aegisgraph/media-decoder-entry": ("decoder", "media_decode"),
    "aegisgraph/native-method-with-tainted-input": ("native_boundary", "native_boundary"),
    "aegisgraph/device-linking-flow": ("control", "qr_device_link"),
    "aegisgraph/key-storage-access": ("control", "crypto_key_lifecycle"),
}


def _location_anchor(
    location: dict[str, Any],
    source_root: Path,
    repo_url: str,
    commit: str,
) -> tuple[str, str, int | None]:
    """Extract (rel_path, anchor, line) from a SARIF physicalLocation."""
    pl = location.get("physicalLocation", {})
    art = pl.get("artifactLocation", {})
    uri = art.get("uri", "")
    region = pl.get("region", {})
    start_line = region.get("startLine")
    if isinstance(start_line, str) and start_line.isdigit():
        start_line = int(start_line)
    if not isinstance(start_line, int):
        start_line = None
    rel_path = relative_source_path(uri, source_root)
    anchor = github_anchor(repo_url, commit, rel_path, start_line)
    return rel_path, anchor, start_line


def from_sarif(
    sarif_path: Path,
    target_key: str,
    target: dict[str, Any],
    source_root: Path | None,
) -> dict[str, Any]:
    """Build an AdapterResult from a CodeQL SARIF file.

    Args:
        sarif_path:  path to merged SARIF (run_queries.sh output).
        target_key:  "signal" | "element-x".
        target:      TARGETS[target_key] dict (with repo_url, commit).
        source_root: filesystem root the SARIF paths are relative to. If
                     None, the adapter will record paths verbatim.
    """
    if not sarif_path.is_file():
        return adapter_result(
            tool="codeql",
            status="skipped_pending_toolchain",
            reason=f"sarif not found at {sarif_path}; CodeQL CLI may be unavailable or DB not built",
        )

    output_hash = sha256_file(sarif_path)
    try:
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return adapter_result(
            tool="codeql",
            status="failed",
            reason=f"could not parse SARIF: {exc}",
            tool_output_hash=output_hash,
        )

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    src_root = source_root or Path("/")

    for run in sarif.get("runs", []):
        rules_by_index: list[str] = []
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rid = rule.get("id", "")
            rules_by_index.append(rid)

        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            if rule_id is None:
                idx = result.get("ruleIndex")
                if isinstance(idx, int) and 0 <= idx < len(rules_by_index):
                    rule_id = rules_by_index[idx]
            if not rule_id or rule_id not in QUERY_NODE_MAP:
                continue
            node_type, path_class = QUERY_NODE_MAP[rule_id]
            message = truncate(result.get("message", {}).get("text", ""))
            for loc in result.get("locations", []):
                rel_path, anchor, line = _location_anchor(loc, src_root, target["repo_url"], target["commit"])
                node_id = stable_node_id(
                    f"codeql.{rule_id.split('/')[-1]}",
                    rule_id,
                    rel_path,
                    str(line or 0),
                )
                if node_id in seen:
                    continue
                seen.add(node_id)
                node = {
                    "id": node_id,
                    "node_type": node_type,
                    "label": message or rule_id,
                    "source_anchor": anchor,
                    "evidence_source": f"{rule_id}:{output_hash}",
                    "_path_class": path_class,  # consumed by assemble.py, stripped before emit
                }
                nodes.append(node)

    return adapter_result(
        tool="codeql",
        status="ran",
        reason=None,
        tool_output_hash=output_hash,
        nodes=nodes,
        edges=edges,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codeql_to_graph")
    parser.add_argument("target_key", choices=["signal", "element-x"])
    parser.add_argument("--sarif", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    target = {"repo_url": args.repo_url, "commit": args.commit}
    result = from_sarif(args.sarif, args.target_key, target, args.source_root)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
