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


def scan_record(record: dict[str, Any]) -> list[SafetyFlag]:
    haystack = "\n".join(_walk_values(record))
    flags: list[SafetyFlag] = []

    for rule, pattern in BLOCKING_PATTERNS.items():
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
