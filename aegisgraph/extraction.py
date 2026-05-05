from __future__ import annotations

from pathlib import Path
from typing import Any

from .constants import STATIC_GENERATED_AT, TARGETS
from .evidence import evidence_ref, finalize_record, provenance
from .io import write_json
from .score import media_parser_score


def _target_anchor(target: dict[str, str]) -> str:
    return f"{target['repo_url']}/tree/{target['commit']}"


def make_media_reachability_record(target_key: str, previous_hash: str | None = None) -> dict[str, Any]:
    target = TARGETS[target_key]
    anchor = _target_anchor(target)
    title = target["name"].replace(" ", "-").upper()
    decoder_label = "Glide or Android platform image decode" if target_key == "signal" else "Coil or Android platform image decode"
    record = {
        "id": f"AG-EV-EXTRACT-{title}-MEDIA-001",
        "version": "v1.0",
        "target": {
            "name": target["name"],
            "repo_url": target["repo_url"],
            "commit": target["commit"],
            "source_policy": target["source_policy"],
        },
        "path_class": "media_decode",
        "nodes": [
            {
                "id": "entry.inbound-media",
                "node_type": "entry_point",
                "label": "Inbound media or attachment ingest",
                "source_anchor": anchor,
                "evidence_source": "target pin from v0.3 public artifact package",
            },
            {
                "id": "handler.media-pipeline",
                "node_type": "handler",
                "label": "Application media handling pipeline",
                "source_anchor": anchor,
                "evidence_source": "phase0 extraction placeholder, anchor-only",
            },
            {
                "id": "decoder.image-stack",
                "node_type": "decoder",
                "label": decoder_label,
                "source_anchor": anchor,
                "evidence_source": "phase0 extraction placeholder, anchor-only",
            },
            {
                "id": "sink.webp-decoder",
                "node_type": "sink",
                "label": "WebP decoding boundary to be validated through ReproChain",
                "source_anchor": "reprochain/vendor/libwebp/README.md",
                "evidence_source": "ReproChain pin pending exact vulnerable/fixed commit decision",
            },
        ],
        "edges": [
            {"from": "entry.inbound-media", "to": "handler.media-pipeline", "relationship": "routes_to"},
            {"from": "handler.media-pipeline", "to": "decoder.image-stack", "relationship": "delegates_decode"},
            {"from": "decoder.image-stack", "to": "sink.webp-decoder", "relationship": "may_reach_platform_or_library_webp_decoder"},
        ],
        "score_vector": media_parser_score(),
        "claim_state": "validation_tasked",
        "validation_task": {
            "id": f"VAL-{title}-MEDIA-REACHABILITY",
            "command": "make extract && make reprochain-map",
            "expected_output": "commit-pinned media path with explicit Android decoder/libwebp indirection limitations",
            "status": "planned",
        },
        "evidence_refs": [
            evidence_ref(
                f"REF-{title}-TARGET-PIN",
                "aegisgraph-extraction",
                "make extract",
                f"{target['public_artifact_id']}:{target['commit']}",
            )
        ],
        "recommendation_refs": [],
        "limitations": (
            "Phase 0 record preserves only source anchors and path hypothesis. It does not assert a Signal or Element "
            "vulnerability, does not redistribute target source, and explicitly leaves the Android platform decoder or "
            "libwebp indirection for later validation."
        ),
        "provenance": provenance("phase0 automated extraction scaffold"),
        "safety_flags": [],
    }
    return finalize_record(record, previous_hash=previous_hash)


def run_extract(root: Path) -> dict[str, Any]:
    previous_hash: str | None = None
    outputs = []
    for target_key, target in TARGETS.items():
        record = make_media_reachability_record(target_key, previous_hash)
        previous_hash = record["hash_chain"]["record_hash"]
        graph = {
            "tool_output_type": "extraction_graph",
            "version": "v1.0",
            "generated_by": "aegisgraph-tier3-research",
            "generated_at": STATIC_GENERATED_AT,
            "safety_posture": "private_by_default",
            "target": target["name"],
            "source_policy": "anchor-only",
            "records": [record],
            "nodes": record["nodes"],
            "edges": record["edges"],
        }
        out_path = root / "extraction" / "output" / target["graph_dir"] / "graph.json"
        write_json(out_path, graph)
        outputs.append(str(out_path.relative_to(root)))
    manifest = {
        "tool_output_type": "extraction_manifest",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "outputs": outputs,
        "status": "phase0_anchor_only",
    }
    write_json(root / "extraction" / "output" / "manifest.json", manifest)
    return manifest
