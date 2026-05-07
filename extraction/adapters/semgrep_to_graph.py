"""Semgrep JSON -> AegisGraph adapter.

Each Semgrep finding becomes a node. Path class and node type are read from
the rule's `metadata.aegisgraph_path_class` and `metadata.aegisgraph_node_type`
keys (set in extraction/semgrep/rules/*.yml).

Output schema mirrors codeql_to_graph.from_sarif: a single AdapterResult.
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
    stable_node_id,
    truncate,
)


_DEFAULT_NODE_TYPE = "handler"


def from_semgrep_json(
    semgrep_path: Path,
    target_key: str,
    target: dict[str, Any],
    source_root: Path | None,
) -> dict[str, Any]:
    if not semgrep_path.is_file():
        return adapter_result(
            tool="semgrep",
            status="skipped_pending_toolchain",
            reason=f"semgrep results not found at {semgrep_path}",
        )

    output_hash = sha256_file(semgrep_path)
    try:
        data = json.loads(semgrep_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return adapter_result(
            tool="semgrep",
            status="failed",
            reason=f"could not parse semgrep JSON: {exc}",
            tool_output_hash=output_hash,
        )

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    src_root = source_root or Path("/")

    for finding in data.get("results", []):
        check_id = finding.get("check_id", "")
        extra = finding.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        path_class = meta.get("aegisgraph_path_class")
        node_type = meta.get("aegisgraph_node_type", _DEFAULT_NODE_TYPE)
        if path_class not in PATH_CLASSES:
            # Unknown rule -> skip rather than emit a schema-invalid node.
            continue
        rel_path = relative_source_path(finding.get("path", ""), src_root)
        start = finding.get("start", {}) or {}
        line = start.get("line")
        if isinstance(line, str) and line.isdigit():
            line = int(line)
        if not isinstance(line, int):
            line = None
        node_id = stable_node_id(
            f"semgrep.{check_id.split('.')[-1]}",
            check_id,
            rel_path,
            str(line or 0),
        )
        if node_id in seen:
            continue
        seen.add(node_id)
        message = truncate(extra.get("message", "") or check_id)
        nodes.append(
            {
                "id": node_id,
                "node_type": node_type,
                "label": message,
                "source_anchor": github_anchor(target["repo_url"], target["commit"], rel_path, line),
                "evidence_source": f"{check_id}:{output_hash}",
                "_path_class": path_class,
            }
        )

    return adapter_result(
        tool="semgrep",
        status="ran",
        tool_output_hash=output_hash,
        nodes=nodes,
        edges=edges,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="semgrep_to_graph")
    parser.add_argument("target_key", choices=["signal", "element-x"])
    parser.add_argument("--semgrep-json", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    target = {"repo_url": args.repo_url, "commit": args.commit}
    result = from_semgrep_json(args.semgrep_json, args.target_key, target, args.source_root)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
