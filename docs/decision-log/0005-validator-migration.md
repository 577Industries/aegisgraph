# 0005 Validator Migration

Decision: maintain a migration adapter for v0.2/v0.3 claim states while making Python and JSON Schema v1.0 canonical for Tier 3 records.

Rationale: the public artifact package already has useful claim discipline. Tier 3 needs a richer evidence contract without breaking the old vocabulary.

Status: accepted.

## Related

- 0010 — schema additive-only (governs migrations from v1 forward)
- 0020 — fact-vector v2 migration (concrete additive migration example)
- 0021 — validator hardening (the validator that enforces both v0.3 and v1 schemas)

## Proposal claims

- C-EVAL-1 — public-package verification workflow / 11 validator checks.
- C-TECH-3 — evidence-graph schema (9 node families + 11 edge types) preserved across migration.

