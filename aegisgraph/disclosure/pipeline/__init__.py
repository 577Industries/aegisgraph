"""Engine 6 (Coordinated Disclosure) pipeline modules.

Submodules:
    vendor_contact_router   : finding -> vendor_registry.yaml lookup
    cert_cc_submission      : CERT/CC VINCE form template fill (manual)
    embargo_timer           : 90d default + per-finding overrides; pure calc
    reviewer_workbench_link : finding_id -> workbench URL placeholder mapping

None of these modules makes network calls. The pipeline is a paper-trail
producer; humans dispatch the rendered mbox files. See
aegisgraph/disclosure/README.md for the operating procedure.
"""

from __future__ import annotations

__all__ = [
    "vendor_contact_router",
    "cert_cc_submission",
    "embargo_timer",
    "reviewer_workbench_link",
]
