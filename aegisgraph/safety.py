from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SafetyFlag:
    rule: str
    level: str
    message: str
    decision: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule": self.rule,
            "level": self.level,
            "message": self.message,
            "decision": self.decision,
        }


BLOCKING_PATTERNS = {
    "live_target_probing": re.compile(r"\b(nmap|masscan|sqlmap|amass|shodan|censys|production account|live target|live probe)\b", re.I),
    "credentialed_interaction": re.compile(r"\b(password=|api[_-]?key|authorization:\s*bearer|private[_ -]?key|client[_-]?secret)\b", re.I),
    "undisclosed_crash_payload": re.compile(r"\b(raw[_ -]?bytes|payload[_ -]?b64|crash[_ -]?input|weaponized|0day|zero-day poc)\b", re.I),
    "target_source_redistribution": re.compile(r"\b(raw[_ -]?source|vendored signal android|vendored element x|target source copy)\b", re.I),
    # v0.4 additions (plan §10): vendor email allowlist + generic vendor-email
    # regex. Any of these in a record means a vendor security contact has
    # leaked into the sanitized export. Org-id-only strings (e.g.
    # "signal_org") do not trip this rule.
    "vendor_contact_in_public_artifact": re.compile(
        r"(?:"
        r"signal-security@|"
        r"security@element\.io|"
        r"security@matrix\.org|"
        r"chromium-security@|"
        r"security@chromium\.org|"
        r"\b[\w.+-]+@(?:signal\.org|element\.io|matrix\.org|chromium\.org|aomedia\.org|strukturag\.com|wire\.com|telegram\.org)\b"
        r")",
        re.I,
    ),
    # v0.4 (plan §10): reviewed_embargoed disclosure-state records must
    # never appear alongside a sanitized_candidate posture marker in the
    # same record. The pattern looks for both substrings co-occurring in
    # the haystack derived from _walk_values; co-occurrence in the same
    # record is the signal of an embargoed-record leak.
    "disclosure_embargoed_leak": re.compile(
        r"(?=.*\breviewed_embargoed\b)(?=.*\bsanitized_candidate\b)",
        re.I | re.S,
    ),
    # v0.4 (plan §10): Java/native stack frame with file + line number.
    # Allowed projections are `stack_trace_hash` and `stack_trace_summary`
    # — the hash-only fields. A raw frame string is blocked. Note the
    # frame-symbol class includes `:` so C++ namespace operators (`::`)
    # match alongside Java/Kotlin dotted names.
    "raw_stack_trace": re.compile(
        r"\bat\s+[\w$.:<>]+\([\w$./\-]+\.(?:java|kt|cc|cpp|c|m|mm|swift)\s*:\s*\d+\)",
        re.I,
    ),
    # v0.4 (plan §10): forbid any source_snippet field longer than 256
    # chars. We detect the field name + a long body in the same record
    # by matching a `source_snippet`-keyed segment with >=256 trailing chars.
    "target_source_snippet": re.compile(
        r"source_snippet\b[\s\S]{256,}",
        re.I,
    ),
    # v0.4 (plan §10): crosssma_target_redistribution catches a URL or
    # long pasted payload (>128 chars) co-occurring with structural
    # description / cross_target_candidate markers in the same record.
    # Witness-hash references are short and won't trip this.
    "crosssma_target_redistribution": re.compile(
        r"(?=.*(?:structural_description|AG-XSMA-|cross_target_candidate))"
        r"(?=.*(?:https?://\S{128,}|[A-Za-z0-9+/=]{128,}))",
        re.S,
    ),
}

OVERCLAIM_PATTERNS = re.compile(r"\b(proves safe|guarantees security|would have prevented|confirmed vulnerability in signal|confirmed vulnerability in element)\b", re.I)


def _walk_values(value: Any) -> list[str]:
    if isinstance(value, dict):
        values: list[str] = []
        for key, child in value.items():
            values.append(str(key))
            values.extend(_walk_values(child))
        return values
    if isinstance(value, list):
        values = []
        for child in value:
            values.extend(_walk_values(child))
        return values
    if value is None:
        return []
    return [str(value)]


def _is_public_artifact_context(record: dict[str, Any]) -> bool:
    """v0.4 helper: True if the record is destined for a public artifact.

    A record is considered public-artifact-destined when:
      - it explicitly carries safety_posture == "sanitized_candidate", OR
      - it explicitly carries a public_export / public_release flag, OR
      - it does NOT mark itself private (engineering-private templates
        and ledger records explicitly carry safety_posture in
        {private_by_default, private_review} or disclosure_status in
        {private_review, disclosed_pending_patch}; those skip rules that
        would otherwise block legitimate engineering content).
    """
    posture = record.get("safety_posture")
    if posture == "sanitized_candidate":
        return True
    if posture in {"private_by_default", "private_review", "engineering_private"}:
        return False
    disclosure_status = record.get("disclosure_status")
    if disclosure_status in {"private_review", "disclosed_pending_patch"}:
        return False
    # Default: public-context assumption. Records intended for engineering-
    # private use (vendor outbound templates etc.) must mark themselves
    # private by setting one of the markers above. This is fail-loud:
    # silence about posture is treated as "may end up in public".
    return True


# Rules that are context-conditional (only fire in public-artifact context).
# These are stripped from the unconditional BLOCKING_PATTERNS sweep and
# evaluated explicitly in scan_record with public-context gating.
_PUBLIC_ARTIFACT_GATED_RULES = frozenset(
    {
        "vendor_contact_in_public_artifact",
        "disclosure_embargoed_leak",
        "raw_stack_trace",
        "target_source_snippet",
        "crosssma_target_redistribution",
    }
)


def scan_record(record: dict[str, Any]) -> list[SafetyFlag]:
    haystack = "\n".join(_walk_values(record))
    flags: list[SafetyFlag] = []

    public_context = _is_public_artifact_context(record)

    for rule, pattern in BLOCKING_PATTERNS.items():
        # v0.4 gating: vendor_contact_in_public_artifact and friends only
        # fire when the record is destined for public release. Engineering-
        # private templates (e.g. outbound vendor letters) still legitimately
        # contain vendor email addresses and embargoed states.
        if rule in _PUBLIC_ARTIFACT_GATED_RULES and not public_context:
            continue
        if pattern.search(haystack):
            flags.append(
                SafetyFlag(
                    rule=rule,
                    level="blocking",
                    message=f"record contains content matching restricted rule {rule}",
                    decision="reject until removed or manually isolated under disclosure controls",
                )
            )

    if OVERCLAIM_PATTERNS.search(haystack):
        flags.append(
            SafetyFlag(
                rule="overclaiming",
                level="blocking",
                message="record uses language that overstates evidence or implies an unvalidated vulnerability claim",
                decision="rewrite as observed, limited, or validation-tasked evidence",
            )
        )

    limitations = str(record.get("limitations", "")).strip()
    if record.get("claim_state") == "accepted" and len(limitations) < 20:
        flags.append(
            SafetyFlag(
                rule="accepted_without_limitations",
                level="blocking",
                message="accepted claims must keep concrete limitations",
                decision="add limitations or lower the claim state",
            )
        )

    if record.get("disclosure_status") in {"private_review", "disclosed_pending_patch"} and "raw_reproducer" in record:
        flags.append(
            SafetyFlag(
                rule="private_finding_raw_reproducer",
                level="blocking",
                message="private findings cannot carry raw reproducers in exportable records",
                decision="move reproducer out of repo and retain only hash/summary",
            )
        )

    return flags


def blocking_flags(flags: list[SafetyFlag]) -> list[SafetyFlag]:
    return [flag for flag in flags if flag.level == "blocking"]


def apply_safety_flags(record: dict[str, Any]) -> dict[str, Any]:
    updated = dict(record)
    flags = [flag.to_dict() for flag in scan_record(updated)]
    updated["safety_flags"] = flags
    return updated
