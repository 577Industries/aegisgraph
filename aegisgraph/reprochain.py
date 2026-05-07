"""ReproChain orchestrator.

Replaces the phase-0 placeholder. Three entrypoints called from
`aegisgraph.cli`:

    build()        : invokes reprochain/build.sh; captures status into
                     reprochain/evidence/build_manifest.json.
    run()          : invokes the built harness binaries against the
                     handcrafted private seed corpus; captures full
                     ASan output to gitignored asan_*.txt logs and
                     emits a scrubbed asan_report_summary.json.
    map_targets()  : reads extraction/output/<target>/graph.json (when
                     extraction has produced CodeQL-anchored output)
                     and emits per-target evidence records under
                     reprochain/mapping/{signal,element-x}.json plus an
                     aggregated reprochain/evidence/mapping.json.

All three are designed to be safe to run on a host that lacks the
clang/cmake toolchain: build.sh reports
`REPROCHAIN_STATUS=blocked` + `REPROCHAIN_REASON=...` and the
orchestrator records that verbatim in the manifest. run() reports
`status="not_run"` if no harness binary is on disk. map_targets() emits
records flagged `extraction_phase` (`anchor_only`, `codeql`, or
`blocked_pending_extraction`) so downstream readers can tell what
fidelity of mapping they're looking at.

Safety contract: this module never writes crash payload bytes, never
writes developer-host paths into committed artifacts, and never
emits records that match the safety scanner's blocking patterns. All
records flow through finalize_record(), which is the integration
stream's tamper-evidence boundary.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .constants import STATIC_GENERATED_AT, TARGETS
from .evidence import evidence_ref, finalize_record, provenance
from .io import canonical_json, sha256_bytes, sha256_file, sha256_text, write_json
from .score import media_parser_score


# ---------------------------------------------------------------------------
# Pinned commit SHAs. Kept in sync with reprochain/vendor/libwebp/COMMIT_PINS.md
# and reprochain/build.sh. Three independent sources is intentional: any
# rotation requires changing all three, which forces a code review of
# the pin choice rather than a quiet override.
# ---------------------------------------------------------------------------

LIBWEBP_VULN_SHA = "7ba44f80f3b94fc0138db159afea770ef06532a0"
LIBWEBP_FIX_SHA = "902bc9190331343b2017211debcec8d2ab87e17a"
LIBWEBP_VULN_SHORT = LIBWEBP_VULN_SHA[:7]
LIBWEBP_FIX_SHORT = LIBWEBP_FIX_SHA[:7]
LIBWEBP_REPO_URL = "https://github.com/webmproject/libwebp"


# ---------------------------------------------------------------------------
# build()
# ---------------------------------------------------------------------------


def _parse_build_sentinel(stdout: str) -> dict[str, str]:
    """Parse REPROCHAIN_STATUS / REPROCHAIN_REASON / REPROCHAIN_DETAIL lines."""
    result: dict[str, str] = {}
    for line in stdout.splitlines():
        for key in ("REPROCHAIN_STATUS", "REPROCHAIN_REASON", "REPROCHAIN_DETAIL"):
            prefix = f"{key}="
            if line.startswith(prefix):
                result[key.lower()] = line[len(prefix) :].strip()
    return result


def _redact_path(text: str, root: Path) -> str:
    """Strip the absolute repo path from log output before committing.

    `reprochain/evidence/build_manifest.json` is committed so the
    `last_command_stderr_tail` field must not leak the developer's
    home directory. Only paths relative to the repo root and the
    relative paths themselves are kept.
    """
    return text.replace(str(root.resolve()), "<repo>")


def build(root: Path) -> dict[str, Any]:
    """Invoke reprochain/build.sh and persist the build manifest.

    Returns a dict matching the tool-output schema. Always writes
    `reprochain/evidence/build_manifest.json`. Status is one of:
      * "ready"                     — build script succeeded; both
                                      harness binaries exist on disk.
      * "blocked_pending_toolchain" — clang/cmake/nm missing.
      * "blocked_pending_submodule" — libwebp submodule init failed.
      * "blocked_pending_pin_mismatch" — pinned SHA not in submodule.
      * "blocked_build_failed"      — script exited non-zero for a
                                      reason that is not one of the
                                      structured "blocked_pending_*"
                                      sentinels.
    """
    script = root / "reprochain" / "build.sh"
    artifacts: dict[str, Any] = {
        "vuln_binary": str(
            (root / "reprochain" / "vendor" / "libwebp" / "cmake-vuln" / "fuzz_webp_decode_vuln").relative_to(root)
        ),
        "fix_binary": str(
            (root / "reprochain" / "vendor" / "libwebp" / "cmake-fix" / "fuzz_webp_decode_fix").relative_to(root)
        ),
        "vuln_archive": str(
            (root / "reprochain" / "vendor" / "libwebp" / "cmake-vuln" / "libwebp-vuln.a").relative_to(root)
        ),
        "fix_archive": str(
            (root / "reprochain" / "vendor" / "libwebp" / "cmake-fix" / "libwebp-fix.a").relative_to(root)
        ),
    }

    manifest: dict[str, Any] = {
        "tool_output_type": "reprochain_build_manifest",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "library": "libwebp",
        "pins": {
            "vulnerable": {
                "sha": LIBWEBP_VULN_SHA,
                "short": LIBWEBP_VULN_SHORT,
                "url": f"{LIBWEBP_REPO_URL}/commit/{LIBWEBP_VULN_SHA}",
            },
            "fixed": {
                "sha": LIBWEBP_FIX_SHA,
                "short": LIBWEBP_FIX_SHORT,
                "url": f"{LIBWEBP_REPO_URL}/commit/{LIBWEBP_FIX_SHA}",
            },
        },
        "artifacts_expected": artifacts,
        "artifacts_present": {
            key: (root / value).is_file() for key, value in artifacts.items()
        },
        "safety_boundary": (
            "Build artifacts are gitignored. ASan is linked (verified by nm). "
            "Harness reads only from local files, never from network sources."
        ),
    }

    if not script.is_file():
        manifest["status"] = "blocked_build_failed"
        manifest["reason"] = "missing_script"
        manifest["detail"] = f"build.sh not found at {script.relative_to(root)}"
        write_json(root / "reprochain" / "evidence" / "build_manifest.json", manifest)
        return manifest

    if not os.access(script, os.X_OK):
        manifest["status"] = "blocked_build_failed"
        manifest["reason"] = "script_not_executable"
        manifest["detail"] = f"chmod +x {script.relative_to(root)}"
        write_json(root / "reprochain" / "evidence" / "build_manifest.json", manifest)
        return manifest

    try:
        completed = subprocess.run(
            [str(script)],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        manifest["status"] = "blocked_build_failed"
        manifest["reason"] = "build_timeout"
        manifest["detail"] = f"build.sh did not complete in {exc.timeout}s"
        write_json(root / "reprochain" / "evidence" / "build_manifest.json", manifest)
        return manifest
    except (OSError, subprocess.SubprocessError) as exc:
        manifest["status"] = "blocked_build_failed"
        manifest["reason"] = "subprocess_error"
        manifest["detail"] = str(exc)
        write_json(root / "reprochain" / "evidence" / "build_manifest.json", manifest)
        return manifest

    sentinel = _parse_build_sentinel(completed.stdout)
    sentinel_status = sentinel.get("reprochain_status")

    if completed.returncode == 0 and sentinel_status == "ready":
        manifest["status"] = "ready"
        # Refresh artifact-present flags now that build claims success.
        manifest["artifacts_present"] = {
            key: (root / value).is_file() for key, value in artifacts.items()
        }
        # If both binaries are present, hash them so reviewers can
        # checksum-compare against an independent rebuild.
        binary_hashes: dict[str, str] = {}
        for key in ("vuln_binary", "fix_binary"):
            path = root / artifacts[key]
            if path.is_file():
                binary_hashes[key] = sha256_file(path)
        manifest["harness_artifact_sha256"] = binary_hashes
    elif completed.returncode == 2 and sentinel_status == "blocked":
        reason = sentinel.get("reprochain_reason", "blocked_pending_toolchain")
        manifest["status"] = reason if reason.startswith("blocked_") else f"blocked_{reason}"
        manifest["reason"] = reason
        manifest["detail"] = sentinel.get("reprochain_detail", "")
    else:
        manifest["status"] = "blocked_build_failed"
        manifest["reason"] = "nonzero_exit"
        manifest["detail"] = (
            f"exit={completed.returncode}; "
            f"stderr_tail={_redact_path(completed.stderr[-400:], root)!r}"
        )

    write_json(root / "reprochain" / "evidence" / "build_manifest.json", manifest)
    return manifest


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

# Top frames we care about for the differential. We summarize ONLY by
# function name, never by source line. The vuln target is
# BuildHuffmanTable; on the fix tree this same call returns 0 cleanly
# instead of writing past `offset[]`.
_INTERESTING_FUNCS = (
    "BuildHuffmanTable",
    "VP8LBuildHuffmanTable",
    "ReadHuffmanCodeLengths",
    "ReadHuffmanCode",
    "DecodeImageStream",
    "VP8LDecodeImage",
    "WebPDecode",
    "WebPDecodeRGBA",
    "LLVMFuzzerTestOneInput",
)

# An ASan stack frame line looks like:
#     #3 0x55d... in BuildHuffmanTable /path/to/huffman_utils.c:172:5
# We only extract the function-name token (group 1). Source path and
# line number are NEVER captured into the committed summary because
# both can leak developer-host info.
_ASAN_FRAME_RE = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)")
_ASAN_HEADER_RE = re.compile(r"==\d+==ERROR:\s*AddressSanitizer:\s*(\S+)")


def _binary_path(root: Path, label: str) -> Path:
    return root / "reprochain" / "vendor" / "libwebp" / f"cmake-{label}" / f"fuzz_webp_decode_{label}"


def _list_seed_inputs(root: Path) -> list[Path]:
    seed_dir = root / "reprochain" / "corpora-private" / "handcrafted"
    if not seed_dir.is_dir():
        return []
    return sorted(
        path
        for path in seed_dir.iterdir()
        if path.is_file() and path.name not in {"README.md", "MANIFEST.json"}
    )


def _refresh_corpus_manifest(root: Path) -> dict[str, Any]:
    """Re-hash every seed file in the handcrafted dir and refresh
    MANIFEST.json. Only sha256 + a structural one-liner per seed are
    persisted; bytes never leave the gitignored seed directory."""
    seeds = []
    for seed in _list_seed_inputs(root):
        seeds.append(
            {
                "path": str(seed.relative_to(root)),
                "size_bytes": seed.stat().st_size,
                "sha256": sha256_file(seed),
                "structural_note": "VP8L lossless WebP, intentionally-malformed Huffman code-length stream (CVE-2023-4863 class)",
            }
        )
    manifest = {
        "tool_output_type": "reprochain_corpus_manifest",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "directory": "reprochain/corpora-private/handcrafted/",
        "policy": (
            "Only sha256 hashes and structural one-liners are committed. "
            "Seed input bytes themselves are gitignored."
        ),
        "seeds": seeds,
    }
    write_json(root / "reprochain" / "corpora-private" / "handcrafted" / "MANIFEST.json", manifest)
    return manifest


def _summarize_asan(log_text: str) -> dict[str, Any]:
    """Extract crash count + top-5 frame function names. No payload
    bytes, no source paths, no line numbers, no addresses."""
    if not log_text:
        return {"crash_count": 0, "top_frames": [], "categories": []}

    headers = _ASAN_HEADER_RE.findall(log_text)
    crash_count = len(headers)
    if crash_count == 0:
        return {"crash_count": 0, "top_frames": [], "categories": []}

    categories = Counter(headers)
    func_counts: Counter[str] = Counter()
    for line in log_text.splitlines():
        match = _ASAN_FRAME_RE.match(line)
        if match:
            func = match.group(1)
            # Strip operator/template noise; keep just the symbol name root.
            func = func.split("(")[0]
            func_counts[func] += 1

    top_frames: list[dict[str, Any]] = []
    for func, count in func_counts.most_common(20):
        if any(name in func for name in _INTERESTING_FUNCS):
            top_frames.append({"function": func, "frame_hits": count})
        if len(top_frames) >= 5:
            break
    if not top_frames:
        # Fall back to plain top-5 if no name hit the interest list, so
        # the summary is never empty when there was a crash.
        for func, count in func_counts.most_common(5):
            top_frames.append({"function": func, "frame_hits": count})

    return {
        "crash_count": crash_count,
        "top_frames": top_frames,
        "categories": [
            {"category": cat, "count": cnt} for cat, cnt in categories.most_common()
        ],
    }


def _run_one_binary(
    root: Path,
    label: str,
    binary: Path,
    seeds: list[Path],
) -> dict[str, Any]:
    """Run one harness binary against every seed file, capture the
    raw ASan output to a gitignored log, and summarize."""
    raw_log_path = root / "reprochain" / "evidence" / f"asan_fuzz_webp_decode_{label}_{LIBWEBP_VULN_SHORT if label == 'vuln' else LIBWEBP_FIX_SHORT}.txt"
    raw_log_path.parent.mkdir(parents=True, exist_ok=True)

    if not seeds:
        # No seeds — record the bare metadata; no execution.
        raw_log_path.write_text("(no seed inputs were present)\n", encoding="utf-8")
        return {
            "binary": str(binary.relative_to(root)),
            "label": label,
            "executed": False,
            "skip_reason": "no_seed_inputs",
            "crash_count": 0,
            "top_frames": [],
            "categories": [],
            "log_path": str(raw_log_path.relative_to(root)),
        }

    # libFuzzer has its own corpus runner. We pass each seed as an
    # individual argument with -runs=1 so each input is decoded once
    # and the binary exits, regardless of crash state.
    cmd = [str(binary), "-runs=1", "-print_final_stats=0"] + [str(s) for s in seeds]
    log_pieces: list[str] = []
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        log_pieces.append(completed.stdout or "")
        log_pieces.append(completed.stderr or "")
    except subprocess.TimeoutExpired as exc:
        log_pieces.append(f"\n(timeout: {exc.timeout}s)\n")

    log_text = "".join(log_pieces)
    raw_log_path.write_text(log_text, encoding="utf-8")
    summary = _summarize_asan(log_text)
    summary.update(
        {
            "binary": str(binary.relative_to(root)),
            "label": label,
            "executed": True,
            "log_path": str(raw_log_path.relative_to(root)),
            "seed_count": len(seeds),
        }
    )
    return summary


def run(root: Path) -> dict[str, Any]:
    """Run vuln + fix harnesses against handcrafted seed corpus.

    Always writes `reprochain/evidence/run_status.json` and
    `reprochain/evidence/asan_report_summary.json`. The summary is the
    only artifact safe for committed evidence; the per-binary raw logs
    live under `reprochain/evidence/asan_fuzz_*.txt` which is
    gitignored.
    """
    seeds = _list_seed_inputs(root)
    _refresh_corpus_manifest(root)

    per_binary: list[dict[str, Any]] = []
    overall_status = "ready"

    for label in ("vuln", "fix"):
        binary = _binary_path(root, label)
        if not binary.is_file():
            per_binary.append(
                {
                    "binary": str(binary.relative_to(root)),
                    "label": label,
                    "executed": False,
                    "skip_reason": "binary_not_built",
                    "crash_count": 0,
                    "top_frames": [],
                    "categories": [],
                }
            )
            overall_status = "not_run"
            continue
        per_binary.append(_run_one_binary(root, label, binary, seeds))

    # The differential assertion: vuln crashed, fix did not. Only
    # populated when both binaries actually executed.
    differential: dict[str, Any] = {}
    vuln_summary = next((s for s in per_binary if s["label"] == "vuln"), {})
    fix_summary = next((s for s in per_binary if s["label"] == "fix"), {})
    if vuln_summary.get("executed") and fix_summary.get("executed"):
        differential = {
            "vuln_crash_count": int(vuln_summary.get("crash_count", 0)),
            "fix_crash_count": int(fix_summary.get("crash_count", 0)),
            "isolates_cve_2023_4863": (
                int(vuln_summary.get("crash_count", 0)) > 0
                and int(fix_summary.get("crash_count", 0)) == 0
            ),
        }

    summary = {
        "tool_output_type": "reprochain_asan_summary",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "binaries": per_binary,
        "differential": differential,
        "scrubbing_policy": (
            "crash_count + top-5 frame function names only. "
            "No payload bytes, no source paths, no line numbers, no addresses."
        ),
    }
    write_json(root / "reprochain" / "evidence" / "asan_report_summary.json", summary)

    status = {
        "tool_output_type": "reprochain_run_status",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "status": overall_status,
        "seed_count": len(seeds),
        "differential": differential,
        "summary_path": "reprochain/evidence/asan_report_summary.json",
        "restricted_material_policy": (
            "Crash-inducing corpus files remain under reprochain/corpora-private "
            "and are excluded from public sanitized export."
        ),
    }
    write_json(root / "reprochain" / "evidence" / "run_status.json", status)
    return status


# ---------------------------------------------------------------------------
# map_targets()
# ---------------------------------------------------------------------------


def _read_extraction_graph(root: Path, target_key: str) -> dict[str, Any] | None:
    target = TARGETS[target_key]
    path = root / "extraction" / "output" / target["graph_dir"] / "graph.json"
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def _detect_extraction_phase(graph: dict[str, Any] | None) -> str:
    """Decide whether extraction has produced full CodeQL-anchored
    output, anchor-only placeholder output, or nothing at all.

    Heuristic: a CodeQL SARIF anchor will contain a per-file path with
    a `#L<line>` fragment. The phase-0 placeholder produces source
    anchors that point only at `tree/<commit>` with no file path.
    """
    if graph is None:
        return "blocked_pending_extraction"
    nodes: list[dict[str, Any]] = []
    if isinstance(graph.get("nodes"), list):
        nodes = graph["nodes"]
    elif isinstance(graph.get("records"), list) and graph["records"]:
        nodes = graph["records"][0].get("nodes", [])
    if not nodes:
        return "blocked_pending_extraction"
    for node in nodes:
        anchor = str(node.get("source_anchor", ""))
        if "#L" in anchor or re.search(r"/blob/[0-9a-f]+/", anchor):
            return "codeql"
    return "anchor_only"


def _decoder_label(target_key: str) -> str:
    return "Glide-mediated decode path" if target_key == "signal" else "Coil-mediated decode path"


def _platform_indirection_text(target_key: str) -> str:
    """Honest description of the Android platform decoder layer.

    The bug class IS reachable through `ImageDecoder` -> libwebp via
    the Android platform codec, but we DO NOT claim a direct
    app->libwebp link unless the extraction stream's CodeQL output
    establishes it. Until then this string makes the indirection
    explicit in the record's `limitations` field, which the safety
    scanner reads.
    """
    return (
        "Reachability is mediated by the Android platform image decoder "
        "(android.graphics.ImageDecoder / BitmapFactory.decodeStream) which on "
        "modern Android delegates WebP decoding to a system codec that links "
        "libwebp. The application code does NOT call libwebp directly; the "
        "indirection means app-level reachability does not, on its own, "
        "establish exploitability against the deployed app."
    )


def _mapping_record(
    target_key: str,
    graph: dict[str, Any] | None,
    phase: str,
    previous_hash: str | None = None,
    *,
    build_status: str | None = None,
    differential: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target = TARGETS[target_key]
    title = target["name"].replace(" ", "-").upper()
    decoder_label = _decoder_label(target_key)
    target_anchor = f"{target['repo_url']}/tree/{target['commit']}"
    libwebp_anchor = f"{LIBWEBP_REPO_URL}/commit/{LIBWEBP_VULN_SHA}"

    # Pull node anchors from the extraction graph when present. Each
    # node carries an evidence_source string that documents how the
    # anchor was produced (CodeQL SARIF, anchor-only placeholder, or
    # repurposed for the libwebp sink).
    extraction_records = (graph or {}).get("records", []) if isinstance(graph, dict) else []
    extraction_nodes: list[dict[str, Any]] = []
    if extraction_records and isinstance(extraction_records[0], dict):
        extraction_nodes = extraction_records[0].get("nodes", []) or []

    def _find_extraction_node(node_id_substr: str) -> dict[str, Any]:
        for node in extraction_nodes:
            if isinstance(node, dict) and node_id_substr in str(node.get("id", "")):
                return node
        return {}

    entry_extract = _find_extraction_node("entry")
    handler_extract = _find_extraction_node("handler") or _find_extraction_node("media-pipeline")
    decoder_extract = _find_extraction_node("decoder")

    nodes = [
        {
            "id": "entry.inbound-media",
            "node_type": "entry_point",
            "label": (
                "MmsAttachment ingest (Signal Android)"
                if target_key == "signal"
                else "Coil ImageRequest ingest (Element X Android)"
            ),
            "source_anchor": str(entry_extract.get("source_anchor", target_anchor)),
            "evidence_source": (
                str(entry_extract.get("evidence_source"))
                if entry_extract.get("evidence_source")
                else f"extraction phase={phase}; target pinned at {target['commit']}"
            ),
        },
        {
            "id": "handler.media-pipeline",
            "node_type": "handler",
            "label": (
                "Glide RequestBuilder.into() handler chain"
                if target_key == "signal"
                else "Coil ImageDecoderDecoder handler chain"
            ),
            "source_anchor": str(handler_extract.get("source_anchor", target_anchor)),
            "evidence_source": (
                str(handler_extract.get("evidence_source"))
                if handler_extract.get("evidence_source")
                else f"extraction phase={phase}; handler boundary, anchor at target tree"
            ),
        },
        {
            "id": "decoder.platform",
            "node_type": "decoder",
            "label": "Android ImageDecoder / BitmapFactory.decodeStream",
            "source_anchor": str(decoder_extract.get("source_anchor", target_anchor)),
            "evidence_source": (
                str(decoder_extract.get("evidence_source"))
                if decoder_extract.get("evidence_source")
                else (
                    f"extraction phase={phase}; system-level decoder boundary, "
                    "platform-mediated to libwebp via codec"
                )
            ),
        },
        {
            "id": "decoder.app-stack",
            "node_type": "decoder",
            "label": decoder_label,
            "source_anchor": str(decoder_extract.get("source_anchor", target_anchor)),
            "evidence_source": (
                f"extraction phase={phase}; app-stack decoder is the immediate caller of the platform decoder"
            ),
        },
        {
            "id": "sink.libwebp-buildhuffmantable",
            "node_type": "sink",
            "label": "libwebp BuildHuffmanTable (CVE-2023-4863, vuln pin 7ba44f8)",
            "source_anchor": libwebp_anchor,
            "evidence_source": (
                "ReproChain harness build manifest; vulnerable static archive at "
                "reprochain/vendor/libwebp/cmake-vuln/libwebp-vuln.a"
            ),
        },
    ]

    edges = [
        {"from": "entry.inbound-media", "to": "handler.media-pipeline", "relationship": "routes_to"},
        {"from": "handler.media-pipeline", "to": "decoder.app-stack", "relationship": "delegates_decode"},
        {"from": "decoder.app-stack", "to": "decoder.platform", "relationship": "platform_indirection"},
        {"from": "decoder.platform", "to": "sink.libwebp-buildhuffmantable", "relationship": "system_codec_links_libwebp"},
    ]

    # Claim state contract (per spec):
    #  - if extraction is missing OR build is blocked, we are still
    #    `validation_tasked` (the path is hypothesized, not verified).
    #  - if build is ready AND differential confirms ASan signal, we
    #    upgrade to `reviewed` for the *prioritization* claim only.
    confirmed_diff = (
        isinstance(differential, dict)
        and bool(differential.get("isolates_cve_2023_4863"))
    )
    if phase == "blocked_pending_extraction":
        claim_state = "validation_tasked"
        validation_status = "blocked"
    elif build_status == "ready" and confirmed_diff:
        claim_state = "reviewed"
        validation_status = "passing"
    else:
        claim_state = "validation_tasked"
        validation_status = "ready" if build_status == "ready" else "blocked"

    limitations_segments = [
        _platform_indirection_text(target_key),
        (
            "ReproChain harness validates the libwebp library-level OOB-write fragility "
            "at the pinned vulnerable commit (7ba44f8) and the absence of that signal at "
            "the pinned fixed commit (902bc91). It does NOT validate exploitability of "
            f"{target['name']} at commit {target['commit']}; that would require "
            "behavioral reproduction against the deployed app, which is out of scope."
        ),
        (
            f"Extraction phase: {phase}. "
            "Anchor-only placeholders in extraction output produce node anchors that "
            "point at the target tree but not at specific source files; CodeQL-derived "
            "extraction will replace those with file/line anchors when it lands."
        ),
    ]

    record = {
        "id": f"AG-EV-REPROCHAIN-{title}-MAP-001",
        "version": "v1.0",
        "target": {
            "name": target["name"],
            "repo_url": target["repo_url"],
            "commit": target["commit"],
            "source_policy": "anchor-only",
        },
        "path_class": "media_decode",
        "nodes": nodes,
        "edges": edges,
        "score_vector": media_parser_score(),
        "claim_state": claim_state,
        "validation_task": {
            "id": f"VAL-REPROCHAIN-{title}",
            "command": "make reprochain-run",
            "expected_output": (
                "fuzz_webp_decode_vuln crash_count > 0; fuzz_webp_decode_fix crash_count == 0; "
                "asan_report_summary.json differential.isolates_cve_2023_4863 == true"
            ),
            "status": validation_status,
        },
        "evidence_refs": [
            evidence_ref(
                f"REF-REPROCHAIN-{title}-PINS",
                "aegisgraph-reprochain",
                "make reprochain-build",
                f"libwebp vuln={LIBWEBP_VULN_SHA} fix={LIBWEBP_FIX_SHA}",
            ),
            evidence_ref(
                f"REF-REPROCHAIN-{title}-RUN",
                "aegisgraph-reprochain",
                "make reprochain-run",
                json.dumps(differential or {}, sort_keys=True),
            ),
        ],
        "recommendation_refs": [],
        "limitations": " ".join(limitations_segments),
        "provenance": provenance(f"reprochain map_targets phase={phase}"),
        "safety_flags": [],
    }
    return finalize_record(record, previous_hash=previous_hash)


def map_targets(root: Path) -> dict[str, Any]:
    """Build per-target evidence records mapping inbound-media to libwebp sink.

    For each TARGET, reads extraction/output/<dir>/graph.json (if any),
    detects the extraction phase, and writes a per-target mapping
    evidence record under reprochain/mapping/<target>.json plus an
    aggregated tool-output manifest at reprochain/evidence/mapping.json.
    """
    # Read the build manifest + asan summary if available so the
    # validation_task status can reflect harness state.
    build_manifest_path = root / "reprochain" / "evidence" / "build_manifest.json"
    asan_summary_path = root / "reprochain" / "evidence" / "asan_report_summary.json"
    build_status: str | None = None
    if build_manifest_path.is_file():
        try:
            build_manifest = json.loads(build_manifest_path.read_text())
            build_status = str(build_manifest.get("status", "")) or None
        except (OSError, json.JSONDecodeError):
            build_status = None
    differential: dict[str, Any] | None = None
    if asan_summary_path.is_file():
        try:
            asan_summary = json.loads(asan_summary_path.read_text())
            diff = asan_summary.get("differential")
            if isinstance(diff, dict):
                differential = diff
        except (OSError, json.JSONDecodeError):
            differential = None

    previous_hash: str | None = None
    records: list[dict[str, Any]] = []
    per_target_writes: list[str] = []
    phases: dict[str, str] = {}
    for target_key in TARGETS:
        graph = _read_extraction_graph(root, target_key)
        phase = _detect_extraction_phase(graph)
        phases[target_key] = phase
        record = _mapping_record(
            target_key,
            graph,
            phase,
            previous_hash,
            build_status=build_status,
            differential=differential,
        )
        previous_hash = record["hash_chain"]["record_hash"]
        records.append(record)
        per_target_path = root / "reprochain" / "mapping" / f"{target_key}.json"
        per_target_doc = {
            "tool_output_type": "reprochain_mapping_target",
            "version": "v1.0",
            "generated_by": "aegisgraph-tier3-research",
            "generated_at": STATIC_GENERATED_AT,
            "safety_posture": "private_by_default",
            "target_key": target_key,
            "extraction_phase": phase,
            "build_status": build_status or "unknown",
            "records": [record],
        }
        write_json(per_target_path, per_target_doc)
        per_target_writes.append(str(per_target_path.relative_to(root)))

    # Aggregate manifest: same shape the original phase-0 placeholder
    # used, plus extra metadata (extraction_phases, build_status,
    # differential pointer) for downstream consumers.
    overall_phase = (
        "blocked_pending_extraction"
        if all(p == "blocked_pending_extraction" for p in phases.values())
        else (
            "codeql"
            if any(p == "codeql" for p in phases.values())
            else "anchor_only"
        )
    )
    manifest = {
        "tool_output_type": "reprochain_mapping",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "extraction_phases": phases,
        "build_status": build_status or "unknown",
        "differential_pointer": "reprochain/evidence/asan_report_summary.json",
        "per_target_outputs": per_target_writes,
        "status": overall_phase,
        "records": records,
    }
    write_json(root / "reprochain" / "evidence" / "mapping.json", manifest)
    return manifest
