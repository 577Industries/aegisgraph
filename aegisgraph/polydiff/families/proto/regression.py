"""PolyDiff proto-family regression run (T-M2.6).

End-to-end flow mirroring the qr + deeplink + opengraph + image-family
regression modules:

  1. Load the anchored corpus (`polydiff/families/proto/regression/
     corpus.json`). Each case carries: case_id, witness_sha256,
     witness_size_bytes, implementations (the wrappers the case is
     designed to disagree on), expected_fact_vector_diff (axis -> [val_a,
     val_b]).

  2. For each case, gather fact vectors from each declared implementation
     wrapper. The default `_fact_vectors_for_case` calls the per-wrapper
     `run(witness_bytes, input_id)` callables; tests monkeypatch this
     function to inject synthesized vectors (no binaries / decoders
     needed).

  3. Compute the fact-vector diff across vectors (per-axis differences).

  4. Classify each disagreement via
     `aegisgraph.polydiff.core.triage.classify_proto_disagreement`.

  5. Emit one AG-DIS-PROTO-* record per case via
     `emit_disagreement_record`. Records carry: witness_sha256 + size
     (hash-only; no payload bytes), implementations_disagreeing@version,
     fact_vector_diff, triage_class + rationale, optional
     historical_cve_reference, reachability mapping, provenance, and
     hash_chain. Each record validates against
     schema/disagreement.schema.json.

  6. Write the regression report + records to evidence/.
     (Tests patch `write_json` so the report is captured rather than
      written to disk.)

The URL, image, opengraph, deeplink, and qr families' `run_regression`
are unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from aegisgraph.evidence import provenance
from aegisgraph.hashchain import attach_hash_chain
from aegisgraph.io import load_json, write_json

from ...core.triage import classify_proto_disagreement
from .wrappers import (
    flatc_runner,
    msgpack_python,
    protoc_gogofaster_stub,
    protoc_python,
)


# Whitelist mapping from implementation id (corpus.json `implementations`
# entries) to the wrapper module. Avoiding dynamic imports keeps the
# attack-surface tight.
_WRAPPER_MAP = {
    "protoc_python": protoc_python,
    "flatc_runner": flatc_runner,
    "msgpack_python": msgpack_python,
    "protoc_gogofaster_stub": protoc_gogofaster_stub,
}

# Version pins parallel family.yaml.
_VERSION_PIN = {
    "protoc_python": "protoc-python@v25.0",
    "flatc_runner": "flatc@v24.3.25",
    "msgpack_python": "msgpack-python@v1.0.8",
    "protoc_gogofaster_stub": "gogo-protobuf-stub@v0.1.0",
}


def _corpus_path(root: Path) -> Path:
    return root / "polydiff" / "families" / "proto" / "regression" / "corpus.json"


def _evidence_dir(root: Path) -> Path:
    return root / "polydiff" / "families" / "proto" / "evidence"


def _regression_dir(root: Path) -> Path:
    return root / "polydiff" / "families" / "proto" / "regression"


def _normalize_case_id(case_id: str) -> str:
    """Map case_id to the schema-required `^AG-DIS-[A-Z0-9-]+$` suffix."""
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
    """AG-DIS-PROTO-<normalized> per schema/disagreement.schema.json."""
    return f"AG-DIS-PROTO-{_normalize_case_id(case_id)}"


def _fact_vectors_for_case(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Default fact-vector gatherer: invoke each implementation's wrapper.

    Tests monkeypatch this function to inject synthesized vectors. The
    proto family does NOT read witness bytes itself in the default
    path — those live in reprochain/corpora-private/ engineering-side
    only. With no bytes to feed, the wrappers return the
    `binary_missing=True` crash envelope.
    """
    vectors: list[dict[str, Any]] = []
    witness_bytes = b""
    for impl_id in case.get("implementations", []):
        wrapper = _WRAPPER_MAP.get(impl_id)
        if wrapper is None:
            continue
        vectors.append(wrapper.run(witness_bytes=witness_bytes, input_id=case["case_id"]))
    return vectors


def _vectors_to_diff(vectors: list[dict[str, Any]]) -> dict[str, list[Any]]:
    """Compute the per-axis disagreement diff across `vectors`."""
    axes = (
        "format_kind",
        "declared_schema_version",
        "message_type_name",
        "field_count",
        "field_unknown_count",
        "oneof_active_field",
        "decoded_field_summary",
        "parser_warnings",
        "decode_outcome",
    )
    diff: dict[str, list[Any]] = {}
    for axis in axes:
        values: list[Any] = [v.get(axis) for v in vectors]
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
    """Produce a sealed AG-DIS-PROTO-* record for `case`.

    The record validates against schema/disagreement.schema.json.
    """
    fact_vector_diff = _vectors_to_diff(vectors)

    impls_seen = [v.get("parser_profile", "unknown") for v in vectors]
    impl_pinned = sorted({_VERSION_PIN.get(p, p) for p in impls_seen})

    triage = classify_proto_disagreement(fact_vector_diff)

    historical = case.get("historical_cve_reference")
    novelty = "rediscovery" if historical else "appears_novel"

    record: dict[str, Any] = {
        "disagreement_id": _disagreement_id(case["case_id"]),
        "version": "v1.0",
        "discovery_engine": "polydiff",
        "family": "proto",
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
            f"PolyDiff proto-family regression case {case['case_id']}"
        ),
    }

    sealed = attach_hash_chain(record, previous_hash=previous_hash)
    return sealed


def _reachability_for_case(case: dict[str, Any]) -> dict[str, list[str]] | None:
    """Construct the reachability block from the case's target list.

    Inlined to match family.yaml without requiring yaml parsing in the
    hot path.
    """
    targets = case.get("reachability_targets") or []
    if not targets:
        return None
    paths = {
        "signal_android": [
            "WebSocketHandler.onMessage -> ProtoMessageDispatcher.dispatch",
        ],
        "element_x_android": [
            "MatrixApi.requestSync -> EventDecoder.decode",
        ],
        "signal_ios": [
            "SocketManagerImpl.didReceive -> ProtoEventDispatcher.dispatch",
        ],
    }
    return {t: paths.get(t, []) for t in targets if t in paths}


def run_regression(root: Path) -> dict[str, Any]:
    """End-to-end proto-family regression run.

    Loads corpus.json, runs the diff engine per case, emits
    AG-DIS-PROTO-* records, and writes the report + records to
    evidence/.

    `write_json` and `_fact_vectors_for_case` are module-level names so
    tests can monkeypatch them.
    """
    corpus = load_json(_corpus_path(root))
    cases: Iterable[dict[str, Any]] = (
        corpus.get("cases", []) if isinstance(corpus, dict) else corpus
    )

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
        case_index.append(
            {
                "case_id": case["case_id"],
                "disagreement_id": record["disagreement_id"],
                "triage_class": record["triage_class"],
                "expected_triage_class": case.get("expected_triage_class"),
                "historical_cve_reference": case.get("historical_cve_reference"),
            }
        )

    report: dict[str, Any] = {
        "tool_output_type": "polydiff_proto_regression_report",
        "version": "v1.0",
        "family": "proto",
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
    "classify_proto_disagreement",
]
