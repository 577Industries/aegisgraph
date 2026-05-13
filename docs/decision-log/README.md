# AegisGraph Tier 3 Research — Architectural Decision Records (ADRs)

This index lists every ADR in this directory. ADRs are accepted, proposed, or
superseded — see the status legend.

## Status legend

- **Accepted**: decision is in force and shapes the codebase
- **Proposed**: decision drafted but pending owner sign-off
- **Superseded by 000X**: replaced by another ADR (none yet)

## Index

| #    | Title                                                | Status   | Date       | Substantiates proposal claims |
|------|------------------------------------------------------|----------|------------|------------------------------|
| 0001 | Repo split (private Tier-3 / public release)         | Accepted | (Phase 0)  | (process; supports C-EVAL-2) |
| 0002 | Private ReproChain handling                          | Accepted | (Phase 0)  | C-NEW-RC, C-EVAL-2 |
| 0003 | libwebp selection (CVE-2023-4863)                    | Accepted (commit-pin gated) | (Phase 0)  | C-NEW-RC |
| 0004 | PolyDiff selection (URL-parser differential)         | Accepted | (Phase 0)  | C-NEW-PD |
| 0005 | Validator migration (v0.2 / v0.3 → v1.0)             | Accepted | (Phase 0)  | C-EVAL-1, C-TECH-3 |
| 0006 | Disclosure ownership                                 | Accepted | 2026-05-12 | C-VAL-2, C-NEW-PD, C-NEW-CD |
| 0007 | libwebp over FORCEDENTRY                             | Accepted | 2026-05-07 | C-NEW-RC |
| 0008 | URL-parser differential over MLS lifecycle           | Accepted | 2026-05-07 | C-NEW-PD |
| 0009 | libwebp CVE-2023-4863 commit pins                    | Accepted | 2026-05-07 | C-NEW-RC |
| 0010 | Schema additive-only policy                          | Accepted | 2026-05-07 | C-TECH-3, C-EVAL-1 |
| 0011 | Public-export human gate                             | Accepted | 2026-05-07 | C-EVAL-2, C-VAL-2 |
| 0012 | Integration merge ready                              | Accepted | 2026-05-07 | (process) |
| 0013 | Schema v2 — discovery-graph additive extension       | Accepted | 2026-05-12 | C-SCHEMA-V2, C-NEW-HG, C-NEW-IC, C-NEW-CS, C-NEW-DP, C-NEW-CD, C-TECH-3 |
| 0014 | Hash-chained coordinated-disclosure ledger            | Accepted | 2026-05-12 | C-NEW-CD, C-DISC-V1..V5, C-EVAL-1 |
| 0020 | PolyDiff fact-vector v2 migration                    | Proposed | 2026-05-07 | C-NEW-PD, C-TECH-3 |
| 0021 | Validator hardening (sanitize-check, traceability, non-mutating mode) | Accepted | 2026-05-07 | C-EVAL-1, C-EVAL-2 |

CETM claim IDs are sourced from
`03_PROPOSAL/active-package/04_evidence/v0.3/cetm.json` (49 claims initially; new claim families `C-SCHEMA-V2`, `C-NEW-HG/IC/CS/DP/CD`, and `C-DISC-V1..V5` are added in the v0.4 CETM extension per the Phase II rollout plan). The
master proposal is at
`03_PROPOSAL/active-package/01_master_proposal/AegisGraph_ASEMA_DP2_Master_Proposal_v0.3.md`.

For the canonical file list:

```
ls docs/decision-log/*.md
```

## How to add a new ADR

1. Pick the next free integer (currently 0015-0019, then 0022+).
2. Filename: `NNNN-short-kebab-title.md`.
3. Body skeleton:

   ```markdown
   # NNNN <Title>

   Status: <accepted | proposed | superseded by NNNN>
   Date: YYYY-MM-DD

   ## Decision
   ## Rationale
   ## Consequences
   ## Related ADRs
   ## Proposal claims
   ```

4. If the ADR governs a schema change, see the schema-delta-via-PR-plus-ADR
   contract in `docs/operating-procedures.md` §2.
5. Add a row to the table above and reference the relevant CETM
   claim_id(s) so the proposal traceability matrix can rehydrate the
   claim → evidence path.
