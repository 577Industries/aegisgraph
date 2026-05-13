# Engine 6 — Coordinated Disclosure

Tamper-evident hash-chained ledger for coordinated vulnerability disclosure events. Records the full lifecycle of every finding promoted past `reviewed`.

## Status

**v0.4 scaffolding.** Ledger format finalized (ADR-0014). Vendor registry populated. No real disclosure entries yet — first contact gated on:

1. Counsel one-time review of disclosure policy + first-letter template (Phase II `T-M1.4`, blocking)
2. ≥1 qualifying finding from PolyDiff Extended / HarnessGen / InvariantCheck reaching `claim_state: reviewed`
3. PI sign-off on the specific first-disclosure target

The Phase II plan recommends **libwebp upstream** as first target (Option A), reasoning documented in `vendor_registry.yaml`.

## Files

| File | Role |
|------|------|
| `__init__.py` | package init |
| `ledger.py` | append-only JSONL reader/writer/verifier; reuses `aegisgraph.hashchain` primitives |
| `ledger.jsonl` | the chain itself (append-only) — starts empty |
| `vendor_registry.yaml` | per-vendor contacts, CNA status, embargo defaults |
| `pipeline/` | TODO: vendor_contact_router, embargo_timer, cert_cc_submission, reviewer_workbench_link |
| `templates/` | TODO: vendor_initial_email.j2, reproduction_steps.j2, cve_request.j2 |
| `claim_states/` | TODO: state-transition extensions (reviewed_embargoed, disclosed_public) |

## Ledger usage (forward-looking)

```python
from aegisgraph.disclosure import ledger
from aegisgraph.evidence import finalize_record

event = {
    "entry_id": "AG-DISC-20260612-0001",
    "version": "v1.0",
    "finding_id": "AG-DIS-IMG-0001",
    "engine_origin": "polydiff",
    "event_type": "vendor_contacted",
    "timestamp": "2026-06-12T10:00:00Z",
    "actor": "577_industries_pi",
    "vendor_contact": "security@chromium.org",
    "embargo_days": 90,
    "embargo_until": "2026-09-10",
    "payload_hash_only": "<sha256>",
    # provenance + safety_flags + hash_chain are filled in by finalize_record
}
finalized = finalize_record(event)  # not yet wired
appended = ledger.append(finalized)
```

## Verification

```bash
# CLI (forward-looking):
aegisgraph disclose ledger --verify  # exit 0 if chain intact
aegisgraph disclose status           # human-readable summary

# Python:
from aegisgraph.disclosure.ledger import verify_chain
errors = verify_chain()
assert errors == [], errors
```

## Public exports

Per sanitize-check Rule 7 (forthcoming in validator-v2), the ledger is **engineering-private**. The public projection strips `vendor_contact` to organization-id-only and includes only entries with `event_type ∈ {cve_assigned, cve_published, disclosure_public}`.

## References

- ADR-0006 — disclosure ownership (PI as named owner)
- ADR-0013 — schema v2 (introduces `disclosure_event` node + new claim states)
- ADR-0014 — hash-chained ledger format
- `SECURITY.md` (workspace root) — canonical disclosure protocol
- Asemarefactor.md "Engine 6" — original design spec
