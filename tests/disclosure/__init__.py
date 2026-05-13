"""Tests for Engine 6 (Coordinated Disclosure) pipeline.

These tests cover the M3-DISC-A scope:
 - vendor_contact_router routes finding -> vendor entry via vendor_registry.yaml
 - embargo_timer pure calculation (90d default, per-finding overrides)
 - Jinja2 template rendering produces safety.scan_record-clean output
 - claim_states.reviewed_embargoed.enter requires prior ledger event
 - `aegisgraph disclose` CLI subcommand smoke

The ledger tamper-evidence is already covered by tests/test_disclosure_ledger.py.
"""
