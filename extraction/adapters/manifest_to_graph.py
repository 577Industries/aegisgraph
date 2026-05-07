"""Manifest analysis -> AegisGraph adapter.

Reads `extraction/output/<target>/manifest-analysis.json` (produced by
`extraction.manifest.manifest_analyzer`) and emits AegisGraph nodes:

- One `entry_point` per (component with `<intent-filter>`) — path_class is
  `deeplink` if any data tag has scheme/host, otherwise `inbound_message`.
- One `control` per declared `<permission>` — path_class
  `crypto_key_lifecycle` (the manifest is the gating control on protected
  data access).
- One `native_boundary` per declared native library — path_class
  `native_boundary`.

When the manifest analysis file is missing the adapter returns
`status="skipped_pending_target_source"` (clones target source is the
manifest analyzer's job, not the adapter's).
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


def _component_path_class(intent_filters: list[dict[str, Any]]) -> str:
    """Heuristic: any data tag with a scheme indicates a deeplink path-class.

    Otherwise it's an inbound_message-style entry point (typical for
    services / receivers that accept system broadcasts).
    """
    for f in intent_filters:
        for d in f.get("data", []):
            if d.get("scheme"):
                return "deeplink"
    return "inbound_message"


def from_manifest_analysis(
    manifest_path: Path,
    target_key: str,
    target: dict[str, Any],
    source_root: Path | None,
) -> dict[str, Any]:
    if not manifest_path.is_file():
        return adapter_result(
            tool="manifest",
            status="skipped_pending_target_source",
            reason=(
                f"manifest analysis not found at {manifest_path}; "
                "manifest_analyzer requires a cloned target source tree"
            ),
        )

    output_hash = sha256_file(manifest_path)
    try:
        analysis_set = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return adapter_result(
            tool="manifest",
            status="failed",
            reason=f"could not parse manifest analysis: {exc}",
            tool_output_hash=output_hash,
        )

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    src_root = source_root or Path("/")

    for analysis in analysis_set.get("analyses", []):
        manifest_fs_path = analysis.get("manifest_path", "")
        rel_manifest = relative_source_path(manifest_fs_path, src_root)

        # 1. Components with intent filters -> entry_point nodes.
        for comp in analysis.get("components", []):
            ifs = comp.get("intent_filters", [])
            if not ifs or not comp.get("exported"):
                continue
            path_class = _component_path_class(ifs)
            comp_block = json.dumps(comp, sort_keys=True)
            comp_hash = sha256_text(comp_block)
            node_id = stable_node_id(
                "manifest.component",
                analysis.get("package", ""),
                comp.get("component_type", ""),
                comp.get("name", ""),
            )
            if node_id in seen:
                continue
            seen.add(node_id)
            label = truncate(
                f"{comp.get('component_type', '')} {comp.get('name', '<anonymous>')} "
                f"(filters={len(ifs)}, exported={comp.get('exported')})"
            )
            nodes.append(
                {
                    "id": node_id,
                    "node_type": "entry_point",
                    "label": label,
                    "source_anchor": github_anchor(target["repo_url"], target["commit"], rel_manifest),
                    "evidence_source": f"manifest:{comp_hash}",
                    "_path_class": path_class,
                }
            )

        # 2. Permissions declared -> control nodes (crypto_key_lifecycle path-class).
        for perm in analysis.get("permissions_declared", []):
            name = perm.get("name", "")
            if not name:
                continue
            perm_hash = sha256_text(json.dumps(perm, sort_keys=True))
            node_id = stable_node_id("manifest.permission", analysis.get("package", ""), name)
            if node_id in seen:
                continue
            seen.add(node_id)
            nodes.append(
                {
                    "id": node_id,
                    "node_type": "control",
                    "label": truncate(f"declared permission {name} ({perm.get('protectionLevel', 'normal')})"),
                    "source_anchor": github_anchor(target["repo_url"], target["commit"], rel_manifest),
                    "evidence_source": f"manifest:{perm_hash}",
                    "_path_class": "crypto_key_lifecycle",
                }
            )

        # 3. Native libraries -> native_boundary nodes.
        for lib in analysis.get("native_libraries", []):
            name = lib.get("name", "")
            if not name:
                continue
            lib_hash = sha256_text(json.dumps(lib, sort_keys=True))
            node_id = stable_node_id("manifest.native_lib", analysis.get("package", ""), name)
            if node_id in seen:
                continue
            seen.add(node_id)
            nodes.append(
                {
                    "id": node_id,
                    "node_type": "native_boundary",
                    "label": truncate(f"native library {name} (required={lib.get('required', 'true')})"),
                    "source_anchor": github_anchor(target["repo_url"], target["commit"], rel_manifest),
                    "evidence_source": f"manifest:{lib_hash}",
                    "_path_class": "native_boundary",
                }
            )

    return adapter_result(
        tool="manifest",
        status="ran",
        tool_output_hash=output_hash,
        nodes=nodes,
        edges=edges,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="manifest_to_graph")
    parser.add_argument("target_key", choices=["signal", "element-x"])
    parser.add_argument("--manifest-json", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    target = {"repo_url": args.repo_url, "commit": args.commit}
    result = from_manifest_analysis(args.manifest_json, args.target_key, target, args.source_root)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
