"""Finding x target matrix -> AG-XSMA-* evidence records.

Given a list of `GraphThread` rows and a target registry, the matrix
renderer produces one AG-XSMA-* record per row. Each record contains:

  * `candidate_id` = AG-XSMA-<source_target_short>-<thread_id>
  * `pattern_type` from the thread (parser_disagreement, etc.)
  * `structural_signature` from the canonical pattern extractor
  * `target_findings` = 1 cell per registry target; cell statuses:
      - confirmed_reachable: the source target (where the thread
        originated)
      - candidate_path: a non-source target whose dependency_snapshot
        contains every dependency_key the thread declares
      - dependency_absent: a non-source target missing at least one
        of the thread's dependency_keys
  * provenance, hash chain (sealed via `finalize_record`)

The default for non-source cells follows plan §15 R-ENG-4:
candidate_path (claim_state=anchored), NOT validation_tasked.

`v03_graph_threads()` returns the 6 baseline threads from the v0.3
evidence corpus (SIG-GP-001..003 + ELX-GP-001..003) so M5.5 can
render a 24-cell baseline matrix without depending on a live
evidence-load pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping

from aegisgraph.constants import STATIC_GENERATED_AT
from aegisgraph.crosssma.pattern_extractor import extract_pattern
from aegisgraph.crosssma.queries.shared_library_check import check_shared_library
from aegisgraph.crosssma.target_registry import Target
from aegisgraph.hashchain import attach_hash_chain


@dataclass(frozen=True)
class GraphThread:
    """One v0.3-style graph-thread row that flows into a matrix record."""

    thread_id: str
    source_target_id: str
    title: str
    path_class: str
    pattern_type: str
    family: str
    axis: str
    implementations: tuple[str, ...] = ()
    source_finding_id: str | None = None
    # Dependencies (library names without version suffix) that the
    # pattern implicates. A target carrying ALL of these in its
    # dependency_snapshot scores candidate_path; missing any -> absent.
    dependency_keys: tuple[str, ...] = field(default_factory=tuple)


def _short_target_tag(target_id: str) -> str:
    """signal-android -> SIG, element-x-android -> ELX, etc.
    Used to form the candidate_id namespace token."""
    head = target_id.split("-")[0]
    if head == "element":
        return "ELX"
    if head == "signal":
        return "SIG"
    if head == "wire":
        return "WIRE"
    if head == "telegram":
        return "TEL"
    # Generic fallback: uppercase first 3 letters of the slug
    return re.sub(r"[^A-Z0-9]", "", head.upper())[:3] or "TGT"


def _candidate_id(thread: GraphThread) -> str:
    tag = _short_target_tag(thread.source_target_id)
    safe_thread = re.sub(r"[^A-Z0-9-]", "-", thread.thread_id.upper())
    # Avoid double-prefixing when thread_id already starts with the
    # short-tag namespace (e.g. SIG-GP-001 from signal-android).
    if safe_thread.startswith(f"{tag}-"):
        return f"AG-XSMA-{safe_thread}"
    return f"AG-XSMA-{tag}-{safe_thread}"


def _cell_status_for_non_source(
    target: Target, dependency_keys: tuple[str, ...]
) -> tuple[str, str | None]:
    """Decide a non-source target's cell status from dependency-key
    matching. Returns (status, evidence_note)."""
    if not dependency_keys:
        # No dependency claim -- default to candidate_path (anchored).
        return "candidate_path", "pattern fan-out; no dependency precondition asserted"
    missing: list[str] = []
    matched: list[str] = []
    for lib in dependency_keys:
        result = check_shared_library(target, lib)
        if result.present:
            matched.append(result.matched_dep or lib)
        else:
            missing.append(lib)
    if missing:
        return (
            "dependency_absent",
            f"missing dependencies: {', '.join(missing)}",
        )
    return (
        "candidate_path",
        f"dependency match: {', '.join(matched)}",
    )


def _build_target_findings(
    thread: GraphThread, registry: Mapping[str, Target]
) -> list[dict[str, object]]:
    cells: list[dict[str, object]] = []
    for target_id in sorted(registry.keys()):
        target = registry[target_id]
        if target.target_id == thread.source_target_id:
            cells.append(
                {
                    "target": target_id,
                    "status": "confirmed_reachable",
                    "finding_id": thread.source_finding_id,
                    "path_id": thread.thread_id,
                    "evidence_note": (
                        f"source thread for {thread.thread_id} "
                        f"(origin {thread.source_finding_id or thread.thread_id})"
                    ),
                }
            )
            continue
        status, note = _cell_status_for_non_source(target, thread.dependency_keys)
        cells.append(
            {
                "target": target_id,
                "status": status,
                "finding_id": None,
                "path_id": None,
                "evidence_note": note,
            }
        )
    return cells


def _build_record(
    thread: GraphThread, registry: Mapping[str, Target]
) -> dict[str, object]:
    fingerprint = extract_pattern(
        {
            "pattern_type": thread.pattern_type,
            "family": thread.family,
            "axis": thread.axis,
            "implementations": list(thread.implementations),
        }
    )
    source_finding_id = thread.source_finding_id or thread.thread_id
    record: dict[str, object] = {
        "candidate_id": _candidate_id(thread),
        "version": "v1.0",
        "discovery_engine": "crosssma",
        "discovery_run_id": None,
        "source_finding_id": source_finding_id,
        "pattern_type": fingerprint.pattern_type,
        "family": fingerprint.family,
        "structural_signature": fingerprint.structural_signature,
        "structural_description": (
            f"{thread.title} (family={fingerprint.family}, axis={fingerprint.axis})"
        ),
        "target_findings": _build_target_findings(thread, registry),
        "validation_state": "structural_only",
        "provenance": {
            "generated_by": "aegisgraph.crosssma.matrix_renderer",
            "generated_at": STATIC_GENERATED_AT,
            "source": (
                f"v0.3 graph_threads / {thread.thread_id} / "
                f"source_finding_id={source_finding_id}"
            ),
            "private_by_default": True,
        },
    }
    return attach_hash_chain(record)


def render_matrix(
    threads: list[GraphThread] | tuple[GraphThread, ...],
    registry: Mapping[str, Target],
) -> list[dict[str, object]]:
    """Render one AG-XSMA-* record per thread, with one cell per
    registry target. The returned list preserves input order so
    callers can pair records to threads by index.
    """
    return [_build_record(thread, registry) for thread in threads]


# ---------------------------------------------------------------------------
# Pre-canned v0.3 graph threads
#
# These mirror the 6 threads in
# `02_PUBLIC_RELEASE/.../aegisgraph-v0.3-evidence.json`.
# We hard-code them here rather than loading the JSON because:
#   1. M5.5 must render the matrix without requiring the public
#      release tree to be present in the worktree;
#   2. The threads are stable v0.3 fixtures; updates ship via this
#      file plus a release-note entry.
# ---------------------------------------------------------------------------

_V03_THREADS: tuple[GraphThread, ...] = (
    GraphThread(
        thread_id="SIG-GP-001",
        source_target_id="signal-android",
        title=(
            "Remote URL in composer to link preview metadata and "
            "thumbnail fetch"
        ),
        path_class="link_preview",
        pattern_type="parser_disagreement",
        family="url",
        axis="link_preview_fetch_pipeline",
        implementations=("java.net.URI", "okhttp"),
        source_finding_id="SIG-LINKPREVIEW",
        dependency_keys=("okhttp",),
    ),
    GraphThread(
        thread_id="SIG-GP-002",
        source_target_id="signal-android",
        title="QR code to linked-device state and approval workflow",
        path_class="qr_device_link",
        pattern_type="structural_code_pattern",
        family="qr",
        axis="device_linking_state_machine",
        implementations=("AddLinkDeviceFragment.onQrCodeScanned",),
        source_finding_id="SIG-QR-LINKDEVICE",
        dependency_keys=(),
    ),
    GraphThread(
        thread_id="SIG-GP-003",
        source_target_id="signal-android",
        title=(
            "Kyber pre-key storage, migration, and protocol buffer "
            "boundary"
        ),
        path_class="crypto_key_lifecycle",
        pattern_type="structural_code_pattern",
        family="pq_protocol_migration",
        axis="prekey_state_lifecycle",
        implementations=("SignalKyberPreKeyStore", "KyberPreKeyTable"),
        source_finding_id="SIG-GROUP-SYNC-PQ",
        dependency_keys=(),
    ),
    GraphThread(
        thread_id="ELX-GP-001",
        source_target_id="element-x-android",
        title=(
            "Matrix, element, and app-link deep links to room and "
            "user navigation"
        ),
        path_class="deeplink",
        pattern_type="structural_code_pattern",
        family="deeplink",
        axis="permalink_room_navigation",
        implementations=("MessagesNode.handleRoomLinkClick",),
        source_finding_id="ELX-MANIFEST-DEEPLINKS",
        dependency_keys=(),
    ),
    GraphThread(
        thread_id="ELX-GP-002",
        source_target_id="element-x-android",
        title=(
            "Linked-device QR flow through desktop/mobile handlers "
            "and secure-channel errors"
        ),
        path_class="qr_device_link",
        pattern_type="structural_code_pattern",
        family="qr",
        axis="qr_linked_device_state_machine",
        implementations=(
            "ScanQrCodeEvent.QrCodeScanned",
            "LinkNewDesktopHandler.handleScannedQrCode",
        ),
        source_finding_id="ELX-QRCODE-DEVICE",
        dependency_keys=(),
    ),
    GraphThread(
        thread_id="ELX-GP-003",
        source_target_id="element-x-android",
        title=(
            "Sync, encrypted-room state, media preview configuration, "
            "and timeline rendering"
        ),
        path_class="sync_state",
        pattern_type="structural_code_pattern",
        family="sync",
        axis="sync_media_preview_composition",
        implementations=(
            "sync_service_state",
            "encrypted_room_state",
            "media_preview_configuration",
        ),
        source_finding_id="ELX-SYNC-MEDIA-MESSAGES",
        dependency_keys=(),
    ),
)


def v03_graph_threads() -> tuple[GraphThread, ...]:
    """Return the 6 v0.3 baseline graph threads (SIG-GP-001..003,
    ELX-GP-001..003) used by M5.5 to populate the initial matrix."""
    return _V03_THREADS


__all__ = [
    "GraphThread",
    "render_matrix",
    "v03_graph_threads",
]
