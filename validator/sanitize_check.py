"""Sanitize-check for the public-sanitized export tree.

This module is the gate that decides whether the public-sanitized export can
be promoted to a public release. It is the *only* place that returns True
for `aegisgraph.export._sanitize_check_passes`; if this module is absent,
broken, or unable to confirm safety, the human authorization gate stays
closed and `release_authorized` remains False.

Rules (each is fail-closed; ANY violation -> exit 1 / scan_export_tree.ok=False):

  1. Forbidden filesystem-path / credential / private-key strings appearing
     anywhere in any tracked path or any text-readable file body. The list
     is derived from validator-export Stream §11.6:
         private[-_]submission, corpora-private, /Users/, /home/, C:\\,
         api_key, bearer\\s..., private_key, BEGIN PRIVATE KEY
     Plus a few additive defenses (AWS access keys, GitHub PATs, JWTs).

  2. Schema-aware findings rules: a record with claim_state=="accepted" must
     also carry a disclosure_status in {public_historical, patched_public,
     not_applicable}. Anything else (private_review, disclosed_pending_patch)
     is a leak — accepted private findings cannot be in a public export.

  3. finding_type=="novel_private_candidate" is forbidden in the public
     tree. Novel-private candidates are the candidate-vulnerability bucket;
     they belong only in private-submission until disclosed and patched.

  4. Every tool-output document (i.e. has top-level `tool_output_type`) must
     have safety_posture=="sanitized_candidate". Anything posted to public/
     with safety_posture in {private_by_default, public_approved} is a
     misclassification.

  5. Embedded crash bytes / payloads. Bytes-in-base64 cannot ride into the
     public tree. We refuse any record with `.bytes_b64`, `.payload`, OR a
     stringified value matching `aegisgraph.safety.BLOCKING_PATTERNS`.
     (Importing aegisgraph for the regex set is intentional; if it fails
     the import — e.g. someone removes safety.py — sanitize-check refuses
     to pretend success.)

  6. Static-only findings cannot be promoted to vulnerability claims. We
     cross-reference: `validation_task.status != "passing"` AND
     `claim_state == "accepted"` is a violation. (A static observation with
     a planned-but-unrun validation task is fine; an *accepted* claim with
     a non-passing validation task is overclaim.)

The module exposes a small public API:

  - is_export_safe(path) -> bool
        Convenience for `aegisgraph.export._sanitize_check_passes`.

  - scan_export_tree(path) -> ScanReport
        Full scan; returns ok flag plus a list of human-readable failure
        messages. Used by `validator.cli sanitize-check`.

The CLI prints one line per failure and exits 1 on any failure; exits 0 on
empty failure list. is_export_safe is the lazy import target from
aegisgraph/export.py — it never raises; on import error or scan exception
it returns False (fail-closed).
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# These extensions are likely to contain text we want to scan for forbidden
# patterns. Binary files (images, PDFs, archives) are excluded from text
# scanning; we still record their presence so the file-path rule can flag
# them. The scan does NOT follow symlinks (defense-in-depth: avoid escape
# from the export root).
_TEXT_EXTENSIONS = frozenset(
    {".json", ".md", ".txt", ".yml", ".yaml", ".csv", ".log", ".html", ".htm"}
)
# Files we *always* skip even if extension looks textual. Currently empty
# but reserved so callers can add transient ignore patterns.
_SKIP_NAMES: frozenset[str] = frozenset()

# Path/content-pattern allowlist (Rule 1 only). These files are documentation
# whose entire purpose is to NAME the things excluded from the public tree
# (e.g. "corpora-private", "private-submission") — running Rule 1 against
# them would generate self-referential false positives.
#
# Schema-aware rules (2-6) still apply to allowlisted files: a markdown doc
# isn't a JSON record so 2-6 are no-ops, but if someone ever ships a
# tool-output JSON named EXCLUSIONS.md (impossible by extension, but for
# defense-in-depth) the structural rules would still catch it. The Rule 1
# skip is the only relaxation.
_RULE1_ALLOWLISTED_NAMES: frozenset[str] = frozenset({"EXCLUSIONS.md"})


# ---------------------------------------------------------------------------
# Forbidden patterns (Rule 1)
# ---------------------------------------------------------------------------

# Each entry is (rule_name, compiled_regex, applies_to). applies_to is a tuple
# of "path", "content", or both — some patterns make sense only in path
# strings (private-submission/), others only in content (BEGIN PRIVATE KEY).
@dataclass(frozen=True)
class _PathPattern:
    rule: str
    regex: re.Pattern[str]
    where: tuple[str, ...]  # subset of {"path", "content"}


def _p(rule: str, pattern: str, where: tuple[str, ...]) -> _PathPattern:
    return _PathPattern(rule=rule, regex=re.compile(pattern, re.IGNORECASE), where=where)


FORBIDDEN_PATTERNS: tuple[_PathPattern, ...] = (
    # Repo-internal private path leakage
    _p("private_submission", r"private[-_]submission", ("path", "content")),
    _p("corpora_private", r"corpora-private", ("path", "content")),
    # Local filesystem path leakage
    _p("posix_user_home", r"/Users/[A-Za-z0-9._-]+", ("path", "content")),
    _p("linux_home", r"/home/[A-Za-z0-9._-]+", ("path", "content")),
    _p("windows_drive", r"[A-Z]:\\\\", ("path", "content")),
    # Credentials / keys
    _p("api_key_token", r"\bapi_key\b", ("content",)),
    _p("bearer_token", r"\bbearer\s+[A-Za-z0-9._\-+/=]{12,}", ("content",)),
    _p("private_key_field", r"\bprivate_key\b", ("content",)),
    _p("pem_private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", ("content",)),
    _p("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b", ("content",)),
    _p("github_pat", r"\bghp_[A-Za-z0-9]{32,}\b", ("content",)),
    _p("jwt_token", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", ("content",)),
)


# ---------------------------------------------------------------------------
# Schema-aware rule helpers
# ---------------------------------------------------------------------------

# Disclosure statuses safe to publish (Rule 2). Anything not in this set is
# considered a private/in-flight leak when paired with claim_state="accepted".
_PUBLIC_SAFE_DISCLOSURES = frozenset(
    {"public_historical", "patched_public", "not_applicable"}
)

_FORBIDDEN_FINDING_TYPES = frozenset({"novel_private_candidate"})

_REQUIRED_PUBLIC_SAFETY_POSTURE = "sanitized_candidate"

# Rule 5 / Rule 9: payload-bearing field names. Anything here being non-empty
# is a blocking violation regardless of file context. v0.4 (plan §10) extends
# this with raw_witness and raw_corpus_input — additional payload surfaces
# introduced by HarnessGen/PolyDiff witness output and CrossSMA crash
# correlation. Plus `source_snippet` belongs only in invariant_violation
# `location` blocks where Rule 8 explicitly forbids it; outside of that we
# also catch the field as a payload-bearing surface at the record level.
_PAYLOAD_FIELD_NAMES = (
    "bytes_b64",
    "payload",
    "raw_bytes",
    "raw_reproducer",
    "raw_witness",
    "raw_corpus_input",
)

# v0.4 Rule 7: disclosure_event records exported publicly must have an
# event_type in this whitelist. Anything else (vendor_contacted,
# embargo_set, etc.) is an in-flight private state and must be redacted.
_PUBLIC_SAFE_DISCLOSURE_EVENT_TYPES = frozenset(
    {"cve_assigned", "cve_published", "disclosure_public"}
)


def _import_blocking_patterns() -> tuple[re.Pattern[str], ...] | None:
    """Best-effort import of aegisgraph.safety.BLOCKING_PATTERNS.

    Returns None if the import fails. Callers must treat None as a hard
    failure (fail-closed): we cannot honor Rule 5's safety-pattern overlap
    without the canonical pattern set.
    """
    try:
        # Import lazily so a broken aegisgraph install doesn't crash CLI
        # boot. validator/cli.py decides what to do with None.
        from aegisgraph.safety import BLOCKING_PATTERNS  # type: ignore[import-not-found]
        return tuple(BLOCKING_PATTERNS.values())
    except Exception:  # pragma: no cover - import-error path
        return None


# ---------------------------------------------------------------------------
# Scan result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Failure:
    rule: str
    where: str  # "path:<relpath>" or "content:<relpath>" or "schema:<relpath>:<record_id>"
    detail: str

    def to_line(self) -> str:
        return f"  [{self.rule}] {self.where} :: {self.detail}"


@dataclass
class ScanReport:
    ok: bool
    failures: list[Failure] = field(default_factory=list)
    files_scanned: int = 0
    schema_records_checked: int = 0

    def add(self, failure: Failure) -> None:
        self.failures.append(failure)
        self.ok = False


# ---------------------------------------------------------------------------
# Walk + scan
# ---------------------------------------------------------------------------


def _iter_files(root: Path) -> Iterable[Path]:
    """Yield every regular file under `root`, sorted, no symlinks followed."""
    if not root.exists():
        return
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            # Skip symlinks: a symlink could escape the export root and
            # produce false negatives or false positives. Public exports
            # MUST be flat trees of regular files.
            continue
        if not path.is_file():
            continue
        if path.name in _SKIP_NAMES:
            continue
        yield path


def _scan_paths_and_content(root: Path, report: ScanReport) -> None:
    """Apply Rule 1 (forbidden patterns) to each file's relpath + content.

    Files in `_RULE1_ALLOWLISTED_NAMES` (e.g. EXCLUSIONS.md) skip Rule 1
    because they are documentation that intentionally names excluded items
    (private-submission, corpora-private). Schema-aware rules 2-6 still
    apply to those files via _scan_schema_documents; for a markdown doc
    that's a no-op.
    """
    for path in _iter_files(root):
        rel = str(path.relative_to(root))
        report.files_scanned += 1
        if path.name in _RULE1_ALLOWLISTED_NAMES:
            # Allowlisted from path + content rules; the file is by-design
            # a description of excluded surfaces. Other rules still apply
            # (but won't match a markdown doc).
            continue
        for entry in FORBIDDEN_PATTERNS:
            if "path" in entry.where and entry.regex.search(rel):
                report.add(
                    Failure(
                        rule=entry.rule,
                        where=f"path:{rel}",
                        detail=f"path matches forbidden pattern /{entry.regex.pattern}/",
                    )
                )
        if path.suffix.lower() not in _TEXT_EXTENSIONS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover - filesystem failure
            report.add(
                Failure(
                    rule="read_error",
                    where=f"path:{rel}",
                    detail=f"could not read text body: {exc}",
                )
            )
            continue
        for entry in FORBIDDEN_PATTERNS:
            if "content" not in entry.where:
                continue
            match = entry.regex.search(text)
            if match:
                report.add(
                    Failure(
                        rule=entry.rule,
                        where=f"content:{rel}",
                        detail=(
                            f"content matches forbidden pattern /{entry.regex.pattern}/ "
                            f"at offset {match.start()}"
                        ),
                    )
                )


def _walk_dict_strings(value: Any) -> Iterable[Any]:
    """Yield every leaf string/None/bool/number under a JSON-like structure."""
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk_dict_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dict_strings(child)
    else:
        yield value


def _check_payload_fields(
    record: dict[str, Any], record_id: str, rel: str, report: ScanReport
) -> None:
    """Rule 5: refuse any record carrying payload-bearing fields."""
    for field_name in _PAYLOAD_FIELD_NAMES:
        if field_name in record and record[field_name] not in (None, "", [], {}):
            report.add(
                Failure(
                    rule="embedded_crash_payload",
                    where=f"schema:{rel}:{record_id}",
                    detail=f"record carries forbidden payload field {field_name!r}",
                )
            )


def _check_blocking_overlap(
    record: dict[str, Any],
    record_id: str,
    rel: str,
    report: ScanReport,
    blocking_patterns: tuple[re.Pattern[str], ...],
) -> None:
    """Rule 5b: refuse if any string under the record matches a BLOCKING pattern.

    This is the bridge to aegisgraph.safety: anything the *private* safety
    scanner blocks (live-target probes, credentialed interaction, etc.)
    must not appear in the public tree. We rely on aegisgraph.safety's
    canonical pattern set so the rules don't drift.
    """
    haystack_parts: list[str] = []
    for value in _walk_dict_strings(record):
        if value is None:
            continue
        haystack_parts.append(str(value))
    haystack = "\n".join(haystack_parts)
    for pattern in blocking_patterns:
        if pattern.search(haystack):
            report.add(
                Failure(
                    rule="aegisgraph_blocking_pattern_overlap",
                    where=f"schema:{rel}:{record_id}",
                    detail=(
                        f"record content matches private-tier blocking pattern "
                        f"/{pattern.pattern}/"
                    ),
                )
            )
            # One match per record is enough; further matches are redundant
            # for the operator who must redact.
            return


def _check_evidence_record(
    record: dict[str, Any],
    rel: str,
    report: ScanReport,
    blocking_patterns: tuple[re.Pattern[str], ...],
) -> None:
    """Apply schema-aware rules (2, 3, 5, 6 + v0.4 7/8/9) to one record.

    v0.4 record-kind dispatch: classifies the record via _detect_record_kind
    and runs the matching v0.4 rule (7 for disclosure_event, 8 for
    invariant_violation, 9 for crash). Rules 2/3/5/5b/6 still apply to
    every kind (they're cheap structural checks).
    """
    # Prefer a kind-specific ID over the generic "id" key.
    record_id = str(
        record.get("id")
        or record.get("entry_id")
        or record.get("violation_id")
        or record.get("crash_id")
        or record.get("candidate_id")
        or "<unknown>"
    )
    report.schema_records_checked += 1

    # Rule 2: accepted claims must have a public-safe disclosure_status.
    if record.get("claim_state") == "accepted":
        ds = record.get("disclosure_status")
        if ds is not None and ds not in _PUBLIC_SAFE_DISCLOSURES:
            report.add(
                Failure(
                    rule="accepted_with_private_disclosure",
                    where=f"schema:{rel}:{record_id}",
                    detail=(
                        f"claim_state=accepted requires disclosure_status in "
                        f"{sorted(_PUBLIC_SAFE_DISCLOSURES)}, got {ds!r}"
                    ),
                )
            )

    # Rule 3: forbidden finding_type values.
    ft = record.get("finding_type")
    if ft in _FORBIDDEN_FINDING_TYPES:
        report.add(
            Failure(
                rule="novel_private_candidate_in_public",
                where=f"schema:{rel}:{record_id}",
                detail=f"finding_type={ft!r} is private-only; must not appear in public sanitized export",
            )
        )

    # Rule 5 (and Rule 9 for crash records, since the payload-fields tuple
    # was extended in v0.4 to cover raw_witness/raw_corpus_input).
    _check_payload_fields(record, record_id, rel, report)

    # Rule 5b: aegisgraph BLOCKING_PATTERNS overlap.
    if blocking_patterns:
        _check_blocking_overlap(record, record_id, rel, report, blocking_patterns)

    # Rule 6: static-only findings cannot be promoted.
    vt = record.get("validation_task")
    if (
        record.get("claim_state") == "accepted"
        and isinstance(vt, dict)
        and vt.get("status") not in (None, "passing")
    ):
        report.add(
            Failure(
                rule="static_only_promoted_to_accepted",
                where=f"schema:{rel}:{record_id}",
                detail=(
                    f"claim_state=accepted requires validation_task.status='passing' "
                    f"or absence; got {vt.get('status')!r}"
                ),
            )
        )

    # v0.4 record-kind dispatch.
    kind = _detect_record_kind(record)
    if kind == "disclosure_event":
        _check_disclosure_event_record(record, rel, report)
    elif kind == "invariant_violation":
        _check_invariant_violation_record(record, rel, report)
    elif kind == "crash":
        _check_crash_record(record, rel, report)


def _check_tool_output(
    document: dict[str, Any],
    rel: str,
    report: ScanReport,
) -> None:
    """Rule 4: every tool-output document under public/ must be sanitized_candidate."""
    posture = document.get("safety_posture")
    if posture != _REQUIRED_PUBLIC_SAFETY_POSTURE:
        report.add(
            Failure(
                rule="tool_output_wrong_safety_posture",
                where=f"schema:{rel}:document",
                detail=(
                    f"tool_output_type document must have safety_posture="
                    f"{_REQUIRED_PUBLIC_SAFETY_POSTURE!r}; got {posture!r}"
                ),
            )
        )


def _records_from_document(document: Any) -> list[dict[str, Any]]:
    """Extract evidence-shaped records from a JSON document.

    Mirrors the loose record-detection logic in
    aegisgraph.validation._records_from_document so we apply the same
    rules to top-level evidence-records, embedded `records`, or
    `evidence_records` lists. Findings (finding.schema.json) are only
    embedded inline; we accept them anywhere they appear with the
    finding_type / disclosure_status keys. v0.4 adds disclosure_events,
    invariant_violations, crashes, disagreements, discovery_runs, and
    cross_target_candidates lists.
    """
    if not isinstance(document, dict):
        return []
    out: list[dict[str, Any]] = []
    if document.get("version") == "v1.0" and (
        str(document.get("id", "")).startswith("AG-EV-")
        or str(document.get("id", "")).startswith("AG-FIND-")
    ):
        out.append(document)
    if isinstance(document.get("records"), list):
        out.extend(r for r in document["records"] if isinstance(r, dict))
    if isinstance(document.get("evidence_records"), list):
        out.extend(r for r in document["evidence_records"] if isinstance(r, dict))
    if isinstance(document.get("findings"), list):
        out.extend(r for r in document["findings"] if isinstance(r, dict))
    # v0.4 additive arrays (plan §10 — public artifact schema additions).
    for key in (
        "disclosure_events",
        "invariant_violations",
        "crashes",
        "disagreements",
        "discovery_runs",
        "cross_target_candidates",
    ):
        if isinstance(document.get(key), list):
            out.extend(r for r in document[key] if isinstance(r, dict))
    return out


def _detect_record_kind(record: dict[str, Any]) -> str | None:
    """Classify a record by its ID prefix or known shape markers.

    Returns one of {disclosure_event, invariant_violation, crash,
    cross_target_candidate, evidence, finding, None}. Used to route to
    the v0.4 Rules 7/8/9.
    """
    # Prefer ID-prefix classification — every v1 record carries one.
    for id_key in ("entry_id", "violation_id", "crash_id", "candidate_id", "id"):
        rid = record.get(id_key)
        if not isinstance(rid, str):
            continue
        if rid.startswith("AG-DISC-"):
            return "disclosure_event"
        if rid.startswith("AG-IV-"):
            return "invariant_violation"
        if rid.startswith("AG-CRASH-"):
            return "crash"
        if rid.startswith("AG-XSMA-"):
            return "cross_target_candidate"
        if rid.startswith("AG-EV-"):
            return "evidence"
        if rid.startswith("AG-FIND-"):
            return "finding"
    # Fallback: structural cues.
    if "event_type" in record and "engine_origin" in record:
        return "disclosure_event"
    if "invariant_id" in record and "sarif_result_uri" in record:
        return "invariant_violation"
    if "crash_sha256" in record or "stack_trace_hash" in record:
        return "crash"
    if "structural_signature" in record and "target_findings" in record:
        return "cross_target_candidate"
    return None


def _check_disclosure_event_record(
    record: dict[str, Any],
    rel: str,
    report: ScanReport,
) -> None:
    """Rule 7 (v0.4): disclosure_event records in public exports.

    Allowed: event_type ∈ _PUBLIC_SAFE_DISCLOSURE_EVENT_TYPES, vendor_contact
    is null or an org-id-only token (no '@'), notes_hash is null. Anything
    else trips a per-failure rule so the operator knows exactly which
    surface to redact.
    """
    record_id = str(record.get("entry_id", record.get("id", "<unknown>")))
    event_type = record.get("event_type")
    if event_type is not None and event_type not in _PUBLIC_SAFE_DISCLOSURE_EVENT_TYPES:
        report.add(
            Failure(
                rule="disclosure_event_private_event_type",
                where=f"schema:{rel}:{record_id}",
                detail=(
                    f"disclosure_event.event_type={event_type!r} is private/in-flight; "
                    f"public exports may only carry "
                    f"{sorted(_PUBLIC_SAFE_DISCLOSURE_EVENT_TYPES)}"
                ),
            )
        )
    vendor_contact = record.get("vendor_contact")
    if isinstance(vendor_contact, str) and "@" in vendor_contact:
        report.add(
            Failure(
                rule="disclosure_event_vendor_contact_populated",
                where=f"schema:{rel}:{record_id}",
                detail=(
                    "disclosure_event.vendor_contact must be redacted to "
                    "organization-id-only in public exports (no '@' permitted)"
                ),
            )
        )
    notes_hash = record.get("notes_hash")
    if notes_hash not in (None, "", []):
        report.add(
            Failure(
                rule="disclosure_event_notes_hash_populated",
                where=f"schema:{rel}:{record_id}",
                detail=(
                    "disclosure_event.notes_hash must be null in public exports; "
                    f"got {notes_hash!r}"
                ),
            )
        )


def _check_invariant_violation_record(
    record: dict[str, Any],
    rel: str,
    report: ScanReport,
) -> None:
    """Rule 8 (v0.4): invariant_violation source-snippet redaction.

    The `location` block allows only repo_url + commit + path + start_line
    (and optionally end_line / start_column). Any `source_snippet` key
    anywhere inside `location` is a leak.
    """
    record_id = str(record.get("violation_id", record.get("id", "<unknown>")))
    location = record.get("location")
    if not isinstance(location, dict):
        return
    if "source_snippet" in location:
        report.add(
            Failure(
                rule="invariant_violation_source_snippet",
                where=f"schema:{rel}:{record_id}",
                detail=(
                    "invariant_violation.location.source_snippet is forbidden; "
                    "public exports must keep location to repo_url + commit + "
                    "path + start_line only"
                ),
            )
        )
    # Also catch a top-level source_snippet at the record level.
    if "source_snippet" in record:
        report.add(
            Failure(
                rule="invariant_violation_source_snippet",
                where=f"schema:{rel}:{record_id}",
                detail=(
                    "invariant_violation.source_snippet at top level is forbidden; "
                    "use sarif_result_uri to reference the engineering-private SARIF"
                ),
            )
        )


def _check_crash_record(
    record: dict[str, Any],
    rel: str,
    report: ScanReport,
) -> None:
    """Rule 9 (v0.4): crash record completeness.

    Every crash record must have crash_sha256 set AND must NOT carry any
    payload-bearing field (covered by Rule 5 / _check_payload_fields with
    the v0.4-extended _PAYLOAD_FIELD_NAMES tuple).
    """
    record_id = str(record.get("crash_id", record.get("id", "<unknown>")))
    sha = record.get("crash_sha256")
    if not isinstance(sha, str) or not sha.strip():
        report.add(
            Failure(
                rule="crash_record_missing_sha256",
                where=f"schema:{rel}:{record_id}",
                detail="crash record must carry a non-empty crash_sha256 field",
            )
        )


def _scan_schema_documents(root: Path, report: ScanReport) -> None:
    """Apply Rules 2, 3, 4, 5, 6 to every JSON document under root."""
    blocking_patterns = _import_blocking_patterns()
    if blocking_patterns is None:
        report.add(
            Failure(
                rule="aegisgraph_safety_unavailable",
                where="env:imports",
                detail=(
                    "could not import aegisgraph.safety.BLOCKING_PATTERNS; "
                    "Rule 5b cannot be evaluated. Refusing to certify export safe."
                ),
            )
        )
        blocking_patterns = ()
    for path in _iter_files(root):
        if path.suffix.lower() != ".json":
            continue
        rel = str(path.relative_to(root))
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            report.add(
                Failure(
                    rule="invalid_json",
                    where=f"path:{rel}",
                    detail=f"json parse failed: {exc}",
                )
            )
            continue
        if isinstance(document, dict) and "tool_output_type" in document:
            _check_tool_output(document, rel, report)
        for record in _records_from_document(document):
            _check_evidence_record(record, rel, report, blocking_patterns)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def scan_export_tree(path: Path | str) -> ScanReport:
    """Scan an export-shaped tree (or single file) and return a ScanReport.

    Hardening contract:
      - Missing path → ScanReport(ok=False) with a `missing_path` failure.
        Empty trees are NOT considered safe (a missing public export must
        not auto-promote release_authorized).
      - Internal exceptions are caught and converted to failure entries
        rather than re-raised (defense-in-depth: this is a gate).
    """
    root = Path(path)
    report = ScanReport(ok=True)
    if not root.exists():
        report.add(
            Failure(
                rule="missing_path",
                where=f"path:{root}",
                detail="export tree does not exist; refusing to certify",
            )
        )
        return report
    try:
        _scan_paths_and_content(root, report)
        _scan_schema_documents(root, report)
    except Exception as exc:  # pragma: no cover - defensive catch
        report.add(
            Failure(
                rule="scanner_exception",
                where=f"path:{root}",
                detail=f"unhandled scanner exception: {exc!r}",
            )
        )
    # If we never visited any file at all, treat as suspicious — empty
    # public-sanitized/ is not a valid release artifact.
    if report.files_scanned == 0 and not report.failures:
        report.add(
            Failure(
                rule="empty_export_tree",
                where=f"path:{root}",
                detail="no files found under export root; refusing to certify",
            )
        )
    return report


def is_export_safe(path: Path | str) -> bool:
    """Convenience wrapper for `aegisgraph.export._sanitize_check_passes`.

    Returns True iff scan_export_tree(path).ok is True. NEVER raises: any
    exception is treated as failure. Importable from aegisgraph/export.py
    via lazy import (no circular import — see validator/__init__.py).
    """
    try:
        return scan_export_tree(path).ok
    except Exception:  # pragma: no cover
        return False


def render_failures(report: ScanReport) -> list[str]:
    """Render scan failures as human-readable lines."""
    if report.ok:
        return [
            f"sanitize-check PASS — {report.files_scanned} files scanned, "
            f"{report.schema_records_checked} records checked, no violations"
        ]
    lines = [
        f"sanitize-check FAIL — {len(report.failures)} violation(s) over "
        f"{report.files_scanned} files / {report.schema_records_checked} records:"
    ]
    for failure in report.failures:
        lines.append(failure.to_line())
    return lines


def main(argv: list[str] | None = None) -> int:
    """Stand-alone entry point: `python -m validator.sanitize_check <path>`."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(
            "usage: python -m validator.sanitize_check <path>",
            file=sys.stderr,
        )
        return 2
    target = args[0]
    report = scan_export_tree(Path(target))
    for line in render_failures(report):
        print(line)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
