"""Shared adapter helpers."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

# AegisGraph node-type and path-class enums are defined in the schema and
# in aegisgraph/constants.py. We mirror them here as constants so the
# adapters never silently emit an out-of-schema value.
NODE_TYPES = (
    "entry_point",
    "handler",
    "parser",
    "decoder",
    "native_boundary",
    "sink",
    "control",
    "validation_task",
    "parser_profile",
    "fact_vector",
)

PATH_CLASSES = (
    "inbound_message",
    "media_decode",
    "link_preview",
    "deeplink",
    "qr_device_link",
    "sync_state",
    "crypto_key_lifecycle",
    "native_boundary",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stable_node_id(prefix: str, *parts: str) -> str:
    """Build a deterministic node-id by hashing the parts.

    `prefix` is human-readable (e.g. "codeql.entry-point-intent"); the hash
    suffix keeps node-ids globally unique across queries+rules+manifests
    while being stable across re-runs.
    """
    raw = "|".join(parts)
    return f"{prefix}.{sha256_text(raw)[:12]}"


_REL_PATH_PREFIX = re.compile(r"^(?:file://)?")


def relative_source_path(absolute_path: str, source_root: Path) -> str:
    """Make an SARIF/semgrep file-uri relative to source_root.

    Returns a forward-slash relative path. If the path can't be made
    relative (e.g. it's already short), returns the cleaned input.
    """
    cleaned = _REL_PATH_PREFIX.sub("", absolute_path).lstrip("/")
    try:
        # Make absolute first if cleaned looks like a relative match against
        # source_root.
        candidate = Path(absolute_path)
        if not candidate.is_absolute():
            candidate = (source_root / cleaned).resolve()
        rel = candidate.resolve().relative_to(source_root.resolve())
        return rel.as_posix()
    except (ValueError, OSError):
        # Path couldn't be normalized to source_root; return it as-is.
        return cleaned.replace("\\", "/")


def github_anchor(repo_url: str, commit: str, rel_path: str, line: int | None = None) -> str:
    """Build a github.com/.../tree/<commit>/<path>#L<line> anchor."""
    base = repo_url.rstrip("/")
    anchor = f"{base}/tree/{commit}/{rel_path}"
    if line is not None and line > 0:
        anchor += f"#L{line}"
    return anchor


def adapter_result(
    tool: str,
    status: str,
    reason: str | None = None,
    tool_output_hash: str | None = None,
    nodes: list[dict[str, Any]] | None = None,
    edges: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Construct the canonical AdapterResult payload."""
    nodes = nodes or []
    edges = edges or []
    node_index = {n["id"]: n for n in nodes}
    return {
        "tool": tool,
        "tool_run_status": {
            "status": status,
            "reason": reason,
            "tool_output_hash": tool_output_hash,
        },
        "nodes": nodes,
        "edges": edges,
        "node_index": node_index,
    }


def load_json_safe(path: Path) -> tuple[Any | None, str | None]:
    """Load JSON; return (data, error_or_none).

    Adapters use this so a single broken raw file doesn't crash the whole
    pipeline — the adapter records `status="failed"` instead.
    """
    if not path.is_file():
        return None, f"missing: {path}"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"could not parse {path}: {exc}"


def truncate(text: str, limit: int = 240) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."
