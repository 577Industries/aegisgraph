"""MobSF JSON -> AegisGraph adapter.

Reads `extraction/output/<target>/mobsf-results.json` (produced by
`extraction.mobsf.run_mobsf`) and emits AegisGraph nodes for the
findings categories MobSF reports out.

Subset focused on AegisGraph path classes:
- Permissions / Manifest issues -> control / entry_point (deeplink path).
- Code analysis findings (e.g. WebView misconfig, weak crypto)
  -> handler / parser nodes (link_preview, crypto_key_lifecycle).
- Network policy bypass (cleartext traffic) -> control (link_preview).
- Binary analysis (lib lists) -> native_boundary (native_boundary).

When MobSF was skipped or failed, the adapter forwards the same status to
the AdapterResult so coverage.json reflects the underlying tool state.
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
    sha256_file,
    sha256_text,
    stable_node_id,
    truncate,
)


def _node_for_finding(
    target: dict[str, Any],
    section: str,
    key: str,
    payload: dict[str, Any] | str,
    output_hash: str,
) -> dict[str, Any] | None:
    """Map one MobSF finding to a node, or None to skip."""
    # Path class / node type per MobSF section.
    SECTION_MAP = {
        "permissions": ("control", "crypto_key_lifecycle"),
        "manifest_analysis": ("entry_point", "deeplink"),
        "code_analysis": ("handler", "link_preview"),
        "binary_analysis": ("native_boundary", "native_boundary"),
        "network_security": ("control", "link_preview"),
        "secrets": ("control", "crypto_key_lifecycle"),
    }
    if section not in SECTION_MAP:
        return None
    node_type, path_class = SECTION_MAP[section]
    block_hash = sha256_text(json.dumps({section: {key: payload}}, sort_keys=True))
    node_id = stable_node_id(f"mobsf.{section}", section, key)
    description = ""
    if isinstance(payload, dict):
        description = (
            payload.get("description")
            or payload.get("title")
            or payload.get("info")
            or payload.get("status")
            or ""
        )
        if isinstance(description, dict):
            description = json.dumps(description, sort_keys=True)
    elif isinstance(payload, str):
        description = payload
    label = truncate(f"{section}/{key}: {description}" if description else f"{section}/{key}")
    # MobSF gives APK-level evidence; we anchor at the repo root because there
    # is no per-line source anchor in static APK analysis. The anchor is
    # honest about that ("APK analysis is whole-app evidence").
    anchor = github_anchor(target["repo_url"], target["commit"], "AndroidManifest.xml")
    return {
        "id": node_id,
        "node_type": node_type,
        "label": label,
        "source_anchor": anchor,
        "evidence_source": f"mobsf:{section}:{block_hash}",
        "_path_class": path_class,
    }


def from_mobsf_results(
    mobsf_path: Path,
    target_key: str,
    target: dict[str, Any],
) -> dict[str, Any]:
    if not mobsf_path.is_file():
        return adapter_result(
            tool="mobsf",
            status="skipped_pending_toolchain",
            reason=(
                f"mobsf-results.json not found at {mobsf_path}; "
                "run extraction/mobsf/run_mobsf.py first or accept the skipped status"
            ),
        )

    output_hash = sha256_file(mobsf_path)
    try:
        data = json.loads(mobsf_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return adapter_result(
            tool="mobsf",
            status="failed",
            reason=f"could not parse mobsf-results.json: {exc}",
            tool_output_hash=output_hash,
        )

    underlying_status = data.get("status")
    underlying_reason = data.get("reason")
    if underlying_status != "ran":
        return adapter_result(
            tool="mobsf",
            status=underlying_status or "skipped_pending_toolchain",
            reason=underlying_reason or "mobsf runner reported non-ran status",
            tool_output_hash=output_hash,
        )

    report = data.get("report", {}) or {}
    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()

    # MobSF's API report shape varies. We sniff a few common section keys.
    for section_key in ("permissions", "manifest_analysis", "code_analysis", "binary_analysis", "network_security", "secrets"):
        section = report.get(section_key)
        if not isinstance(section, dict):
            continue
        for key, value in section.items():
            node = _node_for_finding(target, section_key, str(key), value, output_hash)
            if node is None:
                continue
            if node["id"] in seen:
                continue
            seen.add(node["id"])
            nodes.append(node)

    return adapter_result(
        tool="mobsf",
        status="ran",
        tool_output_hash=output_hash,
        nodes=nodes,
        edges=[],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mobsf_to_graph")
    parser.add_argument("target_key", choices=["signal", "element-x"])
    parser.add_argument("--mobsf-json", type=Path, required=True)
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    target = {"repo_url": args.repo_url, "commit": args.commit}
    result = from_mobsf_results(args.mobsf_json, args.target_key, target)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
