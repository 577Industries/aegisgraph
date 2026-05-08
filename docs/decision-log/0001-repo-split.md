# 0001 Repo Split

Decision: create `01_TIER3_RESEARCH/AegisGraph_Tier3_Research/` as a new private research repo and preserve `02_PUBLIC_RELEASE/ASEMA_Public_GitHub_Artifacts/` as the current public v0.2 artifact repo.

Rationale: Tier 3 work introduces private ReproChain, PolyDiff, extraction, and benchmark outputs that must be gated before any public release. The public repo remains stable until a sanitized export is approved.

Status: accepted.

## Related

- 0002 — private ReproChain handling (lives in the private repo this ADR creates)
- 0011 — public-export human gate (the human-approved sanitized-export boundary referenced above)
- 0012 — integration merge-ready (defines the merge surface used by the private Tier-3 repo)

## Proposal claims

- C-EVAL-2 — sanitize-gate posture is downstream of the repo-split decision (private-default vs. public-frozen).
- C-NOT-1 — the boundary table in the proposal is consistent with this split.

