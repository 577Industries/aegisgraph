# 0006 Disclosure Ownership

Status: **accepted** (resolved as part of Phase II rollout planning; supersedes prior "pending human confirmation").

## Decision

Coordinated-disclosure relationships for findings produced by AegisGraph engines (PolyDiff, HarnessGen, InvariantCheck, CrossSMA, ReproChain, DynamicProbe option-period) are owned by the named PI with structural counsel review at the first vendor contact.

### Roles

- **Disclosure-relationship owner:** Dr. Thomas Waweru (PI). Authoritative signer on `event_type=vendor_contacted` ledger entries (see 0014).
- **Backup contact:** Ajayan Janardhanan, when PI is unavailable >72h.
- **Counsel review:** one-time gate before the *first* vendor-contact letter is sent. Subsequent letters use the approved template; counsel re-review required only on material change to disclosure policy or to the template.
- **CERT/CC fallback:** Day-14 escalation if the contacted vendor does not acknowledge.

### Mechanism

- Per-vendor contact addresses, CNA status, and prior response history are kept as **data** (not code) in `aegisgraph/disclosure/vendor_registry.yaml`. Data updates do not require code review.
- All disclosure events (vendor_contacted, vendor_acknowledged, embargo_set, embargo_extended, vendor_patched, cve_assigned, cve_published, disclosure_public, embargo_expired, escalated_cert_cc, retired) are written to the hash-chained ledger at `aegisgraph/disclosure/ledger.jsonl` per ADR-0014.
- Embargo timer defaults to 90 days CERT/CC-style, configurable per finding via `embargo_days`.
- See workspace `SECURITY.md` for the canonical public-facing disclosure protocol.

### What this ADR does NOT decide

- The mechanism for signed authorization in DynamicProbe (option-period). That lives in `aegisgraph/dynamicprobe/authorization/` with its own ADR when DynamicProbe ships.
- The retention of specific outside counsel (a Phase II M1 task `T-M1.5` per the rollout plan).
- The first real-disclosure target selection. The current plan recommends a libwebp upstream path via the Chrome CNA, but the specific candidate emerges from PolyDiff Extended / HarnessGen triage output, not from this ADR.

## Related

- 0002 — private ReproChain handling (private-default posture covers disclosure-sensitive material)
- 0011 — public-export human gate (gate where disclosure decisions are visible)
- 0013 — schema v2 discovery-graph extension (adds `disclosure_event` node type + `reviewed_embargoed` / `disclosed_public` claim states this ADR depends on)
- 0014 — hash-chained disclosure ledger (the mechanism this ADR's decisions are recorded in)
- 0021 — validator hardening (sanitize-check rejects disclosed-pending-patch records on public export; extended in v0.4 to redact embargoed records)

## Proposal claims

- C-VAL-2 — validator independence boundary references this disclosure posture.
- C-NEW-PD — disclosure handling for any novel-private candidate from PolyDiff.
- C-NEW-CD — Coordinated Disclosure pipeline (Engine 6) — this ADR is the ownership-resolution dependency.

