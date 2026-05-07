"""Adapter unit tests.

Exercise each adapter on synthetic raw input so we lock the
SARIF/Semgrep/Manifest/MobSF -> AegisGraph mapping. Every adapter must:

  * emit zero nodes when its raw input is missing (status="skipped_*")
  * emit nodes with non-empty evidence_source when raw input is well-formed
  * never emit a node carrying a phase0/placeholder token
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extraction.adapters.codeql_to_graph import from_sarif
from extraction.adapters.manifest_to_graph import from_manifest_analysis
from extraction.adapters.mobsf_to_graph import from_mobsf_results
from extraction.adapters.semgrep_to_graph import from_semgrep_json


SIGNAL_TARGET = {
    "name": "Signal Android",
    "repo_url": "https://github.com/signalapp/Signal-Android",
    "commit": "1043851",
    "source_policy": "anchor-only",
    "graph_dir": "signal",
    "public_artifact_id": "signal_android_1043851",
}


# -------------------- CodeQL --------------------


def _sample_sarif() -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {"id": "aegisgraph/media-decoder-entry"},
                            {"id": "aegisgraph/inbound-message-handler"},
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "aegisgraph/media-decoder-entry",
                        "message": {"text": "Glide.with(...).load(...)"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/src/main/java/com/example/MediaUtil.java"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "aegisgraph/inbound-message-handler",
                        "message": {"text": "Method handleMessage(EnvelopeData)"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/src/main/java/com/example/Message.java"},
                                    "region": {"startLine": 100},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }


def test_codeql_adapter_skipped_on_missing_sarif(tmp_path: Path) -> None:
    result = from_sarif(tmp_path / "absent.sarif", "signal", SIGNAL_TARGET, tmp_path)
    assert result["tool"] == "codeql"
    assert result["tool_run_status"]["status"] == "skipped_pending_toolchain"
    assert result["nodes"] == []


def test_codeql_adapter_emits_typed_nodes(tmp_path: Path) -> None:
    sarif = tmp_path / "codeql-merged.sarif"
    sarif.write_text(json.dumps(_sample_sarif()))
    result = from_sarif(sarif, "signal", SIGNAL_TARGET, tmp_path)
    assert result["tool_run_status"]["status"] == "ran"
    assert result["tool_run_status"]["tool_output_hash"]
    types = sorted({n["node_type"] for n in result["nodes"]})
    assert "decoder" in types
    assert "handler" in types
    pcs = sorted({n.get("_path_class") for n in result["nodes"]})
    assert "media_decode" in pcs
    assert "inbound_message" in pcs
    # No phase0 leakage anywhere.
    assert "phase0" not in json.dumps(result)
    # source_anchor must contain the pinned commit.
    for node in result["nodes"]:
        assert "/tree/1043851/" in node["source_anchor"]


# -------------------- Semgrep --------------------


def _sample_semgrep_json() -> dict:
    return {
        "results": [
            {
                "check_id": "aegisgraph.unsafe-deeplink-parse-uri-without-authority-check",
                "path": "app/src/main/java/com/example/DeepLink.java",
                "start": {"line": 17, "col": 5},
                "end": {"line": 17, "col": 80},
                "extra": {
                    "message": "Intent.parseUri without authority validation",
                    "metadata": {
                        "aegisgraph_path_class": "deeplink",
                        "aegisgraph_node_type": "handler",
                    },
                },
            },
            {
                "check_id": "unrelated.rule",
                "path": "x.java",
                "start": {"line": 1, "col": 1},
                "extra": {"message": "ignored", "metadata": {}},
            },
        ]
    }


def test_semgrep_adapter_skipped_on_missing_input(tmp_path: Path) -> None:
    result = from_semgrep_json(tmp_path / "absent.json", "signal", SIGNAL_TARGET, tmp_path)
    assert result["tool_run_status"]["status"] == "skipped_pending_toolchain"


def test_semgrep_adapter_filters_unknown_rules(tmp_path: Path) -> None:
    semgrep_path = tmp_path / "semgrep.json"
    semgrep_path.write_text(json.dumps(_sample_semgrep_json()))
    result = from_semgrep_json(semgrep_path, "signal", SIGNAL_TARGET, tmp_path)
    assert result["tool_run_status"]["status"] == "ran"
    # Only one of the two findings has aegisgraph metadata; the other is filtered.
    assert len(result["nodes"]) == 1
    node = result["nodes"][0]
    assert node["_path_class"] == "deeplink"
    assert node["node_type"] == "handler"
    assert "/tree/1043851/" in node["source_anchor"]


# -------------------- Manifest --------------------


def _sample_manifest_analysis(tmp_path: Path) -> dict:
    return {
        "tool_output_type": "manifest_analysis_set",
        "version": "v1.0",
        "source_root": str(tmp_path),
        "manifest_count": 1,
        "analyses": [
            {
                "tool_output_type": "manifest_analysis",
                "version": "v1.0",
                "manifest_path": str(tmp_path / "app" / "src" / "main" / "AndroidManifest.xml"),
                "package": "com.example",
                "application_name": ".App",
                "permissions_used": ["android.permission.INTERNET"],
                "permissions_declared": [
                    {"name": "com.example.ADMIN", "protectionLevel": "signature"}
                ],
                "native_libraries": [{"name": "libapp.so", "required": "true"}],
                "components": [
                    {
                        "component_type": "activity",
                        "name": ".DeepLinkActivity",
                        "exported": True,
                        "permission": None,
                        "intent_filters": [
                            {
                                "actions": ["android.intent.action.VIEW"],
                                "categories": ["android.intent.category.BROWSABLE"],
                                "data": [{"scheme": "aegisgraph", "host": "open"}],
                            }
                        ],
                    },
                    {
                        "component_type": "service",
                        "name": ".SyncService",
                        "exported": False,
                        "permission": None,
                        "intent_filters": [],
                    },
                ],
                "parse_errors": [],
            }
        ],
    }


def test_manifest_adapter_skipped_when_input_missing(tmp_path: Path) -> None:
    result = from_manifest_analysis(tmp_path / "absent.json", "signal", SIGNAL_TARGET, tmp_path)
    assert result["tool_run_status"]["status"] == "skipped_pending_target_source"


def test_manifest_adapter_emits_entry_point_for_deeplink(tmp_path: Path) -> None:
    inp = tmp_path / "manifest-analysis.json"
    inp.write_text(json.dumps(_sample_manifest_analysis(tmp_path)))
    result = from_manifest_analysis(inp, "signal", SIGNAL_TARGET, tmp_path)
    assert result["tool_run_status"]["status"] == "ran"
    by_type: dict[str, list] = {}
    for n in result["nodes"]:
        by_type.setdefault(n["node_type"], []).append(n)
    assert "entry_point" in by_type
    assert "control" in by_type
    assert "native_boundary" in by_type
    # SyncService is not exported -> no entry_point for it.
    eps = [n for n in by_type["entry_point"] if "SyncService" in n["label"]]
    assert eps == [], "SyncService should not produce an entry_point"


# -------------------- MobSF --------------------


def _sample_mobsf_ran() -> dict:
    return {
        "tool_output_type": "mobsf_results",
        "version": "v1.0",
        "target_key": "signal",
        "status": "ran",
        "image": "opensecurity/mobile-security-framework-mobsf:latest",
        "report": {
            "permissions": {
                "android.permission.READ_CONTACTS": {"status": "dangerous", "info": "Reads user contacts"}
            },
            "code_analysis": {
                "android_logging": {"description": "Logging detected"}
            },
            "binary_analysis": {
                "libssl.so": {"info": "Native library"}
            },
        },
    }


def _sample_mobsf_skipped() -> dict:
    return {
        "tool_output_type": "mobsf_results",
        "version": "v1.0",
        "target_key": "signal",
        "status": "skipped",
        "reason": "docker_unavailable",
        "image": "opensecurity/mobile-security-framework-mobsf:latest",
        "report": None,
    }


def test_mobsf_adapter_skipped_when_runner_skipped(tmp_path: Path) -> None:
    inp = tmp_path / "mobsf-results.json"
    inp.write_text(json.dumps(_sample_mobsf_skipped()))
    result = from_mobsf_results(inp, "signal", SIGNAL_TARGET)
    assert result["tool_run_status"]["status"] == "skipped"
    assert result["tool_run_status"]["reason"] == "docker_unavailable"
    assert result["nodes"] == []


def test_mobsf_adapter_ran_emits_nodes(tmp_path: Path) -> None:
    inp = tmp_path / "mobsf-results.json"
    inp.write_text(json.dumps(_sample_mobsf_ran()))
    result = from_mobsf_results(inp, "signal", SIGNAL_TARGET)
    assert result["tool_run_status"]["status"] == "ran"
    types = sorted({n["node_type"] for n in result["nodes"]})
    assert "control" in types
    assert "native_boundary" in types
    assert "handler" in types
    # Path classes covered.
    pcs = sorted({n["_path_class"] for n in result["nodes"]})
    assert "crypto_key_lifecycle" in pcs
    assert "native_boundary" in pcs
    assert "link_preview" in pcs
