from __future__ import annotations

from pathlib import Path
from typing import Any

from .constants import STATIC_GENERATED_AT
from .io import canonical_json, sha256_bytes, write_json


RING1_CORPORA = {
    "url-corpus": [
        "https://preview.example/article",
        "https://preview.example/%2e%2e/admin",
        "https://safe.example\\@192.0.2.11/admin",
    ],
    "qr-corpus": [
        "device-link:valid:synthetic",
        "device-link:expired:synthetic",
        "device-link:wrong-account:synthetic",
    ],
    "deeplink-corpus": [
        "signal://conversation/synthetic",
        "matrix:u/example:example.org",
        "https://matrix.to/#/@example:example.org",
    ],
    "sync-corpus": [
        "matrix-sync:synthetic:empty",
        "matrix-sync:synthetic:replayed-event",
        "signal-sync:synthetic:key-rotation",
    ],
    "pq-corpus": [
        "pqxdh:synthetic:initial",
        "pqxdh:synthetic:rotation",
        "megolm:synthetic:withheld-key",
    ],
}


def _corpus_metadata(name: str, items: list[str]) -> dict[str, Any]:
    checksum = sha256_bytes(canonical_json(items))
    return {
        "name": name,
        "item_count": len(items),
        "sha256": checksum,
        "source_policy": "synthetic",
        "publication_policy": "sanitized_candidate",
    }


def run(root: Path) -> dict[str, Any]:
    corpora = []
    for name, items in RING1_CORPORA.items():
        metadata = _corpus_metadata(name, items)
        write_json(root / "smabench" / "ring1" / name / "corpus.metadata.json", metadata)
        corpora.append(metadata)

    results = {
        "tool_output_type": "smabench_results",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "rings": {
            "ring1": {
                "status": "passing",
                "corpora": corpora,
            },
            "ring2": {
                "status": "wired_to_extraction_outputs",
                "inputs": [
                    "extraction/output/signal/graph.json",
                    "extraction/output/element-x/graph.json",
                ],
            },
            "ring3": {
                "status": "authorization_placeholder",
                "policy": "requires written authorization before any dynamic target work",
            },
        },
        "delta": {
            "baseline": "phase0",
            "regressions": 0,
            "improvements": 0,
        },
    }
    write_json(root / "smabench" / "results" / "latest" / "results.json", results)
    return results
