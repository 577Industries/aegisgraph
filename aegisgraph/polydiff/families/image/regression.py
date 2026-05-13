"""PolyDiff image-family regression run (T-M2.1).

End-to-end flow per Asemarefactor.md §"Engine 1: PolyDiff Extended":

  1. Load the anchored corpus (`polydiff/families/image/regression/corpus.json`).
     Each case carries: case_id, witness_sha256, witness_size_bytes,
     implementations (the two wrappers the case is designed to disagree
     on), expected_fact_vector_diff (axis -> [val_a, val_b]).

  2. For each case, gather fact vectors from each declared implementation
     wrapper. The default `_fact_vectors_for_case` calls the per-wrapper
     `run(witness_bytes, input_id)` callables; tests monkeypatch this
     function to inject synthesized vectors (no binaries needed).

  3. Compute the fact-vector diff across vectors (per-axis differences).

  4. Classify each disagreement via
     `aegisgraph.polydiff.core.triage.classify_image_disagreement`.

  5. Emit one AG-DIS-IMG-* record per case via `emit_disagreement_record`.
     Records carry: witness_sha256 + size (hash-only; no payload bytes),
     implementations_disagreeing@version, fact_vector_diff,
     triage_class + rationale, optional historical_cve_reference,
     reachability mapping (loaded from family.yaml), provenance, and
     hash_chain. Each record validates against
     schema/disagreement.schema.json.

  6. Write the regression report + the records to evidence/.
     (Tests patch `write_json` so the report is captured rather than
      written to disk.)

The URL family's `run_regression` is unchanged. This module is sibling
and additive.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from aegisgraph.evidence import provenance
from aegisgraph.hashchain import attach_hash_chain
from aegisgraph.io import load_json, repo_root, write_json

from ...core.triage import classify_image_disagreement
from .wrappers import (
    coil_decoder_runner,
    glide_bitmap_runner,
    libavif_cli,
    libheif_cli,
    libwebp_cli,
)


# Whitelist mapping from implementation id (corpus.json `implementations`
# entries) to the wrapper module. Avoiding dynamic imports keeps the
# attack-surface tight.
_WRAPPER_MAP = {
    "libwebp": libwebp_cli,
    "libavif": libavif_cli,
    "libheif": libheif_cli,
    "glide_bitmap": glide_bitmap_runner,
    "coil_decoder": coil_decoder_runner,
}

# Version pins parallel family.yaml. Kept here as a tiny dict so the
# `implementations_disagreeing` records carry `<impl>@<version>` strings
# even when family.yaml is not loaded.
_VERSION_PIN = {
    "libwebp": "libwebp@v1.3.2",
    "libavif": "libavif@v1.0.4",
    "libheif": "libheif@v1.18.2",
    "glide_bitmap": "glide@v4.16.0",
    "coil_decoder": "coil@v2.6.0",
}


def _corpus_path(root: Path) -> Path:
    return root / "polydiff" / "families" / "image" / "regression" / "corpus.json"


def _evidence_dir(root: Path) -> Path:
    return root / "polydiff" / "families" / "image" / "evidence"


def _regression_dir(root: Path) -> Path:
    return root / "polydiff" / "families" / "image" / "regression"


def _normalize_case_id(case_id: str) -> str:
    """Map a case_id to the schema-required `^AG-DIS-[A-Z0-9-]+$` suffix.

    Mirrors `families/url/regression._normalize_record_id`: uppercase,
    keep alphanumerics + dashes, collapse repeated dashes, strip outer.
    """
    out: list[str] = []
    for ch in case_id.upper():
        if ch.isalnum() or ch == "-":
            out.append(ch)
        else:
            out.append("-")
    s = "".join(out)
    while "--" in s:
        s = s.replace("--", "-")
    return s.strip("-")


def _disagreement_id(case_id: str) -> str:
    """AG-DIS-IMG-<normalized> per schema/disagreement.schema.json."""
    return f"AG-DIS-IMG-{_normalize_case_id(case_id)}"


def _fact_vectors_for_case(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Default fact-vector gatherer: invoke each implementation's wrapper.

    Tests monkeypatch this function to inject synthesized vectors. The
    image family does NOT read witness bytes itself — those live in
    reprochain/corpora-private/ engineering-side only. In a real run, the
    caller would resolve the private path from INDEX.json and pass the
    bytes here. By default, with no bytes to feed, the wrappers return
    the `binary_missing=True` crash envelope.
    """
    vectors: list[dict[str, Any]] = []
    witness_bytes = b""  # default: empty; real bytes loaded by operator from private corpus
    for impl_id in case.get("implementations", []):
        wrapper = _WRAPPER_MAP.get(impl_id)
        if wrapper is None:
            continue
        vectors.append(wrapper.run(witness_bytes=witness_bytes, input_id=case["case_id"]))
    return vectors


def _vectors_to_diff(vectors: list[dict[str, Any]]) -> dict[str, list[Any]]:
    """Compute the per-axis disagreement diff across `vectors`.

    Mirror of polydiff.disagreement.detector.detect but for image axes.
    Returns a dict {axis: [values]} where values diverge across vectors.
    """
    axes = (
        "dimensions",
        "color_space",
        "alpha_premultiplied",
        "frame_count",
        "first_pixel_rgba",
        "decode_outcome",
        "parser_warnings",
    )
    diff: dict[str, list[Any]] = {}
    for axis in axes:
        values: list[Any] = [v.get(axis) for v in vectors]
        # Skip axes where every observation is the same (no disagreement).
        seen = []
        for val in values:
            frozen = _freeze(val)
            if frozen not in [_freeze(x) for x in seen]:
                seen.append(val)
        if len(seen) > 1:
            diff[axis] = values
    return diff


def _freeze(v: Any) -> Any:
    if isinstance(v, list):
        return tuple(_freeze(x) for x in v)
    if isinstance(v, dict):
        return tuple(sorted((k, _freeze(val)) for k, val in v.items()))
    return v


def emit_disagreement_record(
    *,
    case: dict[str, Any],
    vectors: list[dict[str, Any]],
    previous_hash: str | None,
) -> dict[str, Any]:
    """Produce a sealed AG-DIS-IMG-* record for `case`.

    The record validates against schema/disagreement.schema.json. It
    carries:
      - disagreement_id            (AG-DIS-IMG-<case>)
      - version, discovery_engine  (constants)
      - family                     ("image")
      - witness_sha256, witness_size_bytes (from corpus.json pin)
      - implementations_disagreeing (impl@version per family.yaml)
      - fact_vector_diff           (per-axis divergence values)
      - triage_class + rationale   (classify_image_disagreement output)
      - historical_cve_reference   (optional)
      - reachability               (loaded from family.yaml)
      - provenance, hash_chain     (standard)
    """
    fact_vector_diff = _vectors_to_diff(vectors)

    impls_seen = [v.get("parser_profile", "unknown") for v in vectors]
    impl_pinned = sorted({_VERSION_PIN.get(p, p) for p in impls_seen})

    triage = classify_image_disagreement(fact_vector_diff)

    historical = case.get("historical_cve_reference")
    novelty = "rediscovery" if historical else "appears_novel"

    record: dict[str, Any] = {
        "disagreement_id": _disagreement_id(case["case_id"]),
        "version": "v1.0",
        "discovery_engine": "polydiff",
        "family": "image",
        "discovery_run_id": None,
        "witness_sha256": case["witness_sha256"],
        "witness_size_bytes": case["witness_size_bytes"],
        "implementations_disagreeing": impl_pinned,
        "fact_vector_diff": fact_vector_diff,
        "triage_class": triage["triage_class"],
        "triage_rationale": triage["triage_rationale"],
        "reachability": _reachability_for_case(case),
        "historical_cve_reference": historical,
        "novelty": novelty,
        "provenance": provenance(
            f"PolyDiff image-family regression case {case['case_id']}"
        ),
    }

    sealed = attach_hash_chain(record, previous_hash=previous_hash)
    return sealed


def _reachability_for_case(case: dict[str, Any]) -> dict[str, list[str]] | None:
    """Construct the reachability block from the case's target list.

    Reads from family.yaml when possible; falls back to a minimal map so
    tests don't depend on yaml parsing.
    """
    targets = case.get("reachability_targets") or []
    if not targets:
        return None
    # Inlined reachability strings matching family.yaml. Kept here so the
    # regression run works without yaml-loading; family.yaml remains the
    # human-readable source of truth.
    paths = {
        "signal_android": [
            "SignalAttachment.requireBitmap -> Glide.with().load().submit()",
        ],
        "element_x_android": [
            "MediaRepository.fetchAttachment -> Coil.ImageLoader.execute",
        ],
    }
    return {t: paths.get(t, []) for t in targets if t in paths}


def run_regression(root: Path) -> dict[str, Any]:
    """End-to-end image-family regression run.

    Loads corpus.json, runs the diff engine per case, emits AG-DIS-IMG-*
    records, and writes the report + records to evidence/.

    `write_json` and `_fact_vectors_for_case` are module-level names so
    tests can monkeypatch them.
    """
    corpus = load_json(_corpus_path(root))
    cases: Iterable[dict[str, Any]] = corpus.get("cases", []) if isinstance(corpus, dict) else corpus

    records: list[dict[str, Any]] = []
    case_index: list[dict[str, Any]] = []
    previous_hash: str | None = None

    for case in cases:
        vectors = _fact_vectors_for_case(case)
        record = emit_disagreement_record(
            case=case, vectors=vectors, previous_hash=previous_hash
        )
        previous_hash = record["hash_chain"]["record_hash"]
        records.append(record)
        case_index.append({
            "case_id": case["case_id"],
            "disagreement_id": record["disagreement_id"],
            "triage_class": record["triage_class"],
            "expected_triage_class": case.get("expected_triage_class"),
            "historical_cve_reference": case.get("historical_cve_reference"),
        })

    report: dict[str, Any] = {
        "tool_output_type": "polydiff_image_regression_report",
        "version": "v1.0",
        "family": "image",
        "generated_by": "aegisgraph-tier3-research",
        "safety_posture": "private_by_default",
        "records_emitted": len(records),
        "cases_index": case_index,
        "records": records,
    }
    write_json(_regression_dir(root) / "report.json", report)
    write_json(
        _evidence_dir(root) / "regression.disagreements.json",
        {"records": records},
    )
    return report


__all__ = [
    "run_regression",
    "emit_disagreement_record",
    "classify_image_disagreement",
]
