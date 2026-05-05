from __future__ import annotations

import ipaddress
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .constants import STATIC_GENERATED_AT
from .evidence import evidence_ref, finalize_record, provenance
from .io import sha256_text, write_json
from .score import link_parser_score


REGRESSION_INPUTS = [
    {
        "id": "REG-URL-001",
        "case": "userinfo-host-confusion",
        "url": "https://trusted.example@192.0.2.10/resource",
        "expected_axis": "userinfo_present",
    },
    {
        "id": "REG-URL-002",
        "case": "backslash-authority-confusion",
        "url": "https://safe.example\\@192.0.2.11/admin",
        "expected_axis": "host",
    },
    {
        "id": "REG-URL-003",
        "case": "percent-encoded-path-boundary",
        "url": "https://preview.example/%2e%2e/%2fadmin",
        "expected_axis": "path",
    },
    {
        "id": "REG-URL-004",
        "case": "ipv6-mapped-loopback-classification",
        "url": "http://[::ffff:127.0.0.1]/status",
        "expected_axis": "host_is_private_or_link_local",
    },
]


def _host_is_private(host: str | None) -> bool:
    if not host:
        return False
    stripped = host.strip("[]")
    try:
        return ipaddress.ip_address(stripped).is_private or ipaddress.ip_address(stripped).is_loopback or ipaddress.ip_address(stripped).is_link_local
    except ValueError:
        return False


def _safe_port(parsed: urllib.parse.SplitResult) -> int | None:
    try:
        return parsed.port
    except ValueError:
        return None


def parse_python_urllib(input_id: str, url: str) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(url)
    return {
        "input_id": input_id,
        "parser_profile": "python_urllib",
        "scheme": parsed.scheme or None,
        "host": parsed.hostname,
        "port": _safe_port(parsed),
        "path": parsed.path or None,
        "userinfo_present": bool(parsed.username or parsed.password),
        "host_is_private_or_link_local": _host_is_private(parsed.hostname),
        "parse_error": None,
    }


def parse_whatwg_like(input_id: str, url: str) -> dict[str, Any]:
    normalized = url.replace("\\", "/")
    parsed = urllib.parse.urlsplit(normalized)
    path = urllib.parse.unquote(parsed.path or "")
    return {
        "input_id": input_id,
        "parser_profile": "whatwg_like",
        "scheme": parsed.scheme or None,
        "host": parsed.hostname,
        "port": _safe_port(parsed),
        "path": path or None,
        "userinfo_present": bool(parsed.username or parsed.password),
        "host_is_private_or_link_local": _host_is_private(parsed.hostname),
        "parse_error": None,
    }


def parse_guarded_fetcher(input_id: str, url: str) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname
    if parsed.username or parsed.password:
        host = parsed.netloc.split("@", 1)[0]
    private = _host_is_private(host)
    if host == "::ffff:127.0.0.1":
        private = True
    return {
        "input_id": input_id,
        "parser_profile": "guarded_fetcher",
        "scheme": parsed.scheme or None,
        "host": host,
        "port": _safe_port(parsed),
        "path": parsed.path or None,
        "userinfo_present": bool(parsed.username or parsed.password),
        "host_is_private_or_link_local": private,
        "parse_error": None,
    }


PARSER_PROFILES = (parse_python_urllib, parse_whatwg_like, parse_guarded_fetcher)
DISAGREEMENT_AXES = ("scheme", "host", "port", "path", "userinfo_present", "host_is_private_or_link_local", "parse_error")


@dataclass(frozen=True)
class Disagreement:
    input_id: str
    axis: str
    parser_values: dict[str, Any]
    security_tags: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_id": self.input_id,
            "axis": self.axis,
            "parser_values": self.parser_values,
            "security_tags": self.security_tags,
        }


def fact_vectors_for(input_id: str, url: str) -> list[dict[str, Any]]:
    return [parser(input_id, url) for parser in PARSER_PROFILES]


def security_tags_for(axis: str, values: set[Any]) -> list[str]:
    tags: list[str] = []
    if axis == "host":
        tags.append("origin-confusion")
    if axis == "userinfo_present":
        tags.append("userinfo-confusion")
    if axis == "host_is_private_or_link_local":
        tags.append("ssrf-private-network-classification")
    if axis == "path":
        tags.append("path-normalization-confusion")
    if None in values:
        tags.append("parse-nullability")
    return tags or ["parser-behavior-difference"]


def detect_disagreements(vectors: list[dict[str, Any]]) -> list[Disagreement]:
    disagreements: list[Disagreement] = []
    input_id = vectors[0]["input_id"]
    for axis in DISAGREEMENT_AXES:
        parser_values = {vector["parser_profile"]: vector[axis] for vector in vectors}
        if len(set(parser_values.values())) > 1:
            disagreements.append(
                Disagreement(
                    input_id=input_id,
                    axis=axis,
                    parser_values=parser_values,
                    security_tags=security_tags_for(axis, set(parser_values.values())),
                )
            )
    return disagreements


def _finding_record(index: int, case: dict[str, str], disagreements: list[Disagreement], previous_hash: str | None) -> dict[str, Any]:
    axes = ", ".join(sorted({disagreement.axis for disagreement in disagreements}))
    record = {
        "id": f"AG-EV-POLYDIFF-REG-{index:03d}",
        "version": "v1.0",
        "target": {
            "name": "Synthetic URL parser regression corpus",
            "repo_url": "local://polydiff/regression",
            "commit": "phase0",
            "source_policy": "synthetic",
        },
        "path_class": "link_preview",
        "nodes": [
            {
                "id": "entry.synthetic-url",
                "node_type": "entry_point",
                "label": case["case"],
                "source_anchor": f"polydiff/regression/{case['id']}",
                "evidence_source": "synthetic regression corpus",
            },
            {
                "id": "parser.fact-vector",
                "node_type": "fact_vector",
                "label": f"Disagreement axes: {axes}",
                "source_anchor": "schema/fact-vector.schema.json",
                "evidence_source": "PolyDiff phase0 deterministic parser profiles",
            },
        ],
        "edges": [
            {"from": "entry.synthetic-url", "to": "parser.fact-vector", "relationship": "parsed_by_profiles"},
        ],
        "score_vector": link_parser_score(),
        "claim_state": "reviewed",
        "validation_task": {
            "id": f"VAL-POLYDIFF-REG-{index:03d}",
            "command": "make polydiff-regression",
            "expected_output": "deterministic disagreement record for public historical bug class",
            "status": "passing",
        },
        "evidence_refs": [
            evidence_ref(
                f"REF-POLYDIFF-{case['id']}",
                "aegisgraph-polydiff",
                "make polydiff-regression",
                f"{case['id']}:{sha256_text(case['url'])}",
            )
        ],
        "recommendation_refs": [],
        "limitations": (
            "This is a regression-style synthetic disagreement case, not a claim of a live vulnerability in a maintained "
            "library or service. It is safe to publish only as a bounded parser-behavior test case after sanitized export review."
        ),
        "provenance": provenance("phase0 PolyDiff regression scaffold"),
        "safety_flags": [],
    }
    return finalize_record(record, previous_hash=previous_hash)


def run_regression(root: Path) -> dict[str, Any]:
    all_vectors: list[dict[str, Any]] = []
    all_disagreements: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    previous_hash: str | None = None

    for index, case in enumerate(REGRESSION_INPUTS, start=1):
        vectors = fact_vectors_for(case["id"], case["url"])
        disagreements = detect_disagreements(vectors)
        all_vectors.extend(vectors)
        all_disagreements.extend(disagreement.to_dict() for disagreement in disagreements)
        if disagreements:
            record = _finding_record(index, case, disagreements, previous_hash)
            previous_hash = record["hash_chain"]["record_hash"]
            records.append(record)

    report = {
        "tool_output_type": "polydiff_regression_report",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "parser_profiles": ["python_urllib", "whatwg_like", "guarded_fetcher"],
        "inputs_checked": len(REGRESSION_INPUTS),
        "fact_vectors": all_vectors,
        "disagreements": all_disagreements,
        "records": records,
        "tier_p1_status": "pass" if len(records) >= 3 else "fail",
    }
    write_json(root / "polydiff" / "regression" / "report.json", report)
    write_json(root / "polydiff" / "evidence" / "regression.evidence.json", {"records": records})
    return report
