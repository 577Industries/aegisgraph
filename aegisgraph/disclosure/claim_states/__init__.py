"""Higher-level claim-state enforcement for disclosure transitions.

The underlying state machine lives in `aegisgraph/claims.py`. These
modules enforce the additional semantic invariant that disclosure-
related state transitions require a corresponding ledger event AND
the prior state to be appropriate:

  reviewed -> reviewed_embargoed  : requires vendor_contacted event
  reviewed_embargoed -> disclosed_public : requires embargo_expired,
                                            cve_published, or
                                            disclosure_public event
"""

from __future__ import annotations

__all__ = ["reviewed_embargoed", "disclosed_public"]
