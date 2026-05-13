"""CERT/CC VINCE form filler — manual template, no live HTTP.

CERT/CC is the Day-14 fallback per ADR-0006 when a vendor is unresponsive.
This module produces a filled VINCE-shaped form (rendered text) that the
operator manually submits at https://www.kb.cert.org/vuls/report/.

Per the task constraint: NO live HTTP, no SMTP, no auto-submit. We
render text into aegisgraph/disclosure/outgoing/<finding_id>.cert-cc.txt
for human dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegisgraph.io import repo_root


CERT_CC_URL = "https://www.kb.cert.org/vuls/report/"


@dataclass(frozen=True)
class CertCcSubmission:
    """A prepared CERT/CC submission ready for human review + manual filing."""

    finding_id: str
    output_path: Path
    rendered_text: str
    target_url: str = CERT_CC_URL


def _outgoing_dir(root: Path | None = None) -> Path:
    base = root or repo_root()
    return base / "aegisgraph" / "disclosure" / "outgoing"


def prepare_submission(
    finding_id: str,
    vendor_id: str,
    summary: str,
    triage_class: str,
    witness_sha256: str,
    witness_minimized_bytes: int,
    days_since_contact: int,
    root: Path | None = None,
) -> CertCcSubmission:
    """Render the CERT/CC VINCE form content for a finding.

    Writes to aegisgraph/disclosure/outgoing/<finding_id>.cert-cc.txt.
    The output is plain text intended for manual paste into the VINCE
    form fields. Does NOT submit.
    """
    body = _render_form(
        finding_id=finding_id,
        vendor_id=vendor_id,
        summary=summary,
        triage_class=triage_class,
        witness_sha256=witness_sha256,
        witness_minimized_bytes=witness_minimized_bytes,
        days_since_contact=days_since_contact,
    )
    outgoing = _outgoing_dir(root)
    outgoing.mkdir(parents=True, exist_ok=True)
    target = outgoing / f"{finding_id}.cert-cc.txt"
    target.write_text(body, encoding="utf-8")
    return CertCcSubmission(
        finding_id=finding_id,
        output_path=target,
        rendered_text=body,
    )


def _render_form(
    finding_id: str,
    vendor_id: str,
    summary: str,
    triage_class: str,
    witness_sha256: str,
    witness_minimized_bytes: int,
    days_since_contact: int,
) -> str:
    """Plain-text render of the VINCE form fields.

    Deliberately conservative wording — no exploit claims, no live-target
    references, no embedded payload bytes. The witness is referenced by
    SHA-256 + minimized size only.
    """
    return (
        "CERT/CC VINCE Report — Prepared for Manual Submission\n"
        f"Submit at: {CERT_CC_URL}\n"
        "\n"
        "[Reporter]\n"
        "  Organization: 577 Industries\n"
        "  Contact: disclosure@577.industries\n"
        "\n"
        f"[Vulnerability ID (researcher tracking)]\n  {finding_id}\n"
        "\n"
        f"[Affected Vendor]\n  {vendor_id}\n"
        "\n"
        f"[Triage Class]\n  {triage_class}\n"
        "\n"
        "[Summary]\n"
        f"  {summary}\n"
        "\n"
        "[Reproduction]\n"
        "  A minimized witness is available under coordinated disclosure.\n"
        f"  Witness SHA-256: {witness_sha256}\n"
        f"  Minimized size:  {witness_minimized_bytes} bytes\n"
        "  No payload bytes are included in this report; the witness is\n"
        "  held privately and can be shared with vendor / CERT/CC over an\n"
        "  agreed secure channel.\n"
        "\n"
        "[Vendor Contact Attempts]\n"
        f"  Days since initial vendor contact: {days_since_contact}\n"
        "  No response or insufficient response within the agreed window.\n"
        "\n"
        "[Coordination Requested]\n"
        "  CERT/CC mediation per Day-14 fallback policy (ADR-0006).\n"
        "  Embargo: 90 days from initial vendor contact.\n"
        "\n"
        "[Limitations]\n"
        "  This is a coordinated-disclosure handoff. The finding is a\n"
        "  reproducible decode-outcome divergence; no exploit chain is\n"
        "  asserted.\n"
    )
