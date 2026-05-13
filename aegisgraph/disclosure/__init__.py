"""Engine 6: Coordinated Disclosure.

Tamper-evident hash-chained ledger for coordinated vulnerability disclosure
events. Records the lifecycle of every finding from
`reviewed → reviewed_embargoed → disclosed_public`.

ADR-0006 names PI Waweru as disclosure-relationship owner.
ADR-0013 introduces the `disclosure_event` node type + `reviewed_embargoed`
and `disclosed_public` claim states.
ADR-0014 specifies the JSONL ledger format and hash-chain semantics.
"""

from __future__ import annotations

__all__ = ["ledger"]
