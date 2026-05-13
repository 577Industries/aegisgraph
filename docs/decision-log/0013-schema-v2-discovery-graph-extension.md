# 0013 Schema v2 — Discovery-Graph Additive Extension

Status: **accepted** (integration stream owns enforcement).

## Context

The Asemarefactor reframing introduces six discovery engines (PolyDiff Extended, HarnessGen, InvariantCheck, CrossSMA, DynamicProbe, Coordinated Disclosure) plus a coordinated-disclosure pipeline. Each engine emits structured records the evidence graph must accommodate. ADR-0010 mandates additive-only schema evolution and ADR-0020 already exercised this for fact-vector v2. This ADR enumerates the v2 additions for the discovery graph and asserts they are additive.

## Decision

Schema v2 extends the v1.0 evidence graph contract by:

### 1. Six new `node_type` enum values (in `schema/evidence.schema.json` `$defs.node.properties.node_type.enum`)

- `discovery_run` — single engine execution record
- `crash` — HarnessGen / DynamicProbe / ReproChain crash record (hash-only)
- `disagreement` — PolyDiff differential-fuzzing disagreement
- `invariant_violation` — InvariantCheck SARIF result wrapped in evidence envelope
- `cross_target_candidate` — CrossSMA structural-pattern match across SMAs
- `disclosure_event` — Coordinated Disclosure ledger event

All ten v1 node_type values (`entry_point`, `handler`, `parser`, `decoder`, `native_boundary`, `sink`, `control`, `validation_task`, `parser_profile`, `fact_vector`) remain present and unchanged. Enum extension is a loosening per ADR-0010 rule 3.

### 2. Two new `claim_state` enum values

- `reviewed_embargoed` — finding validated, vendor contacted, embargo timer active
- `disclosed_public` — embargo expired OR vendor confirmed fix; finding now public evidence

Placed in `CLAIM_STATES` ordering between `reviewed` and `accepted` so the existing monotonic transition rule (`idx(next) >= idx(prev)`) in `aegisgraph/claims.py:transition_allowed` accommodates them without modification. All eight v1 claim states remain present.

### 3. Six new edge relationship values

Emitted via the existing `edge.relationship` string field (no schema break, no enum constraint at the JSON-Schema layer):

- `generated_by_engine` — finding ← engine
- `corroborated_by` — finding ← finding (multi-engine confirmation)
- `contradicted_by` — finding ← finding (one engine yes, another no)
- `analogous_to` — cross-target structural match
- `supersedes` — newer finding replaces older
- `disclosed_via` — finding → disclosure event

A new `tests/test_schema_v1_v2_compatibility.py` exercises spelling consistency.

### 4. Two new optional `score_vector` dimensions

- `engine_corroboration` — boolean-ish numeric (0..1): finding produced by ≥2 engines independently?
- `exploitability_evidence` — boolean-ish numeric (0..1): HarnessGen crash or DynamicProbe trace present?

Both nullable (`type: ["number", "null"]`, `default: null`) and absent from `required`. v1 records that omit them validate unchanged. v1 weights stay at 100; v2 records may rebalance in code (`aegisgraph/score.py:normalize_score_vector`) without touching the schema.

### 5. Three new optional top-level fields

- `disclosure_status` — extends existing sanitize-check rule 2 enum (`public_historical`, `patched_public`, `not_applicable`, `private_review`, `disclosed_pending_patch`) with three new values: `embargoed`, `disclosed_public`, `disclosed_patched`. Backed in the schema as `type: ["string", "null"]`.
- `discovery_engine` — which engine produced the record (polydiff | harnessgen | invariantcheck | crosssma | dynamicprobe | reprochain | disclosure | manual).
- `finding_type` — finding category (reachability_observation | differential_disagreement | invariant_violation | harness_crash | cross_target_candidate | disclosure_event | novel_private_candidate). The existing `novel_private_candidate` value matches the value sanitize-check already forbids in public exports per ADR-0021.

All three nullable, defaulted to `null`, absent from `required`. v1 records validate unchanged.

### 6. Six new sibling JSON-Schema files (under `schema/`)

- `discovery-run.schema.json`
- `crash.schema.json`
- `disagreement.schema.json`
- `invariant-violation.schema.json`
- `cross-target-candidate.schema.json`
- `disclosure-event.schema.json`

Each is a Draft 2020-12 schema with `$id` matching the convention `https://577.industries/aegisgraph/schema/<name>.schema.json` and `version: v1.0`. These are *new* schemas, not v2-of-existing-schemas; they don't follow the `.proposed.json` migration path from ADR-0010 §"v2 process" because there is no v1 schema being replaced.

## What this ADR does NOT change

- No v1 field is removed.
- No v1 enum value is removed or constrained.
- No new field is required.
- No `pattern`, `minimum`, `minLength`, or `additionalProperties` is tightened.
- No filename is renamed (per ADR-0010 rule 4).
- No existing `total` weight on `score_vector` is changed. The two new score dimensions are additive and v1 records keep their existing `total` values byte-stable.

## Verification

The regression test `tests/test_schema_v1_v2_compatibility.py` (added with this ADR) is the wall:

1. **Re-validation:** every v1 evidence record currently committed under `extraction/output/`, `reprochain/evidence/`, `polydiff/evidence/`, and `exports/` re-validates under the v2 schema.
2. **Hash stability:** every v1 record's `hash_chain.record_hash` recomputes to the same byte value (`json-v1-sorted-no-hash-chain` canonicalization unchanged).
3. **Enum extension presence:** the new claim_state and node_type enum values appear in the schema.
4. **Optional-field discipline:** new score_vector dims and top-level fields are in `properties` but NOT in `required`.
5. **Sibling schemas:** all six new files are present and parseable.

The `tests/test_schema_validation.py` parametrized fixture auto-discovers the six new schema files and asserts each is a valid Draft 2020-12 schema.

## Why

- DARPA/ASEMA submission manifest hashes records. Any breakage of v1 hash stability invalidates the v0.3 public release tarball (SHA `3ce05fbf…`).
- Six engines emit records on every reproduce. A breaking change in `evidence.schema.json` would silently invalidate downstream consumers (validator, sanitize-check, export).
- The discovery-graph reframe is meaningless if it forces a hash-resetting v2 migration during a 24-month Phase II execution window.

## Out of scope

- Cryptographic signing of disclosure_event records. See ADR-0014 (the ledger), which leaves `signature: null` in v0.4 with PKI integration deferred.
- The score-vector rebalancing within the new 100 budget. Lives in `aegisgraph/score.py`, not in the schema.
- DynamicProbe-specific record shapes. Will live in `schema/dynamicprobe-*.schema.json` if/when needed during option period; the existing `crash.schema.json` covers the option-period crash records as of v0.4.

## Related

- 0010 — schema additive-only migration policy (the rule set this ADR observes)
- 0014 — hash-chained disclosure ledger (depends on `disclosure-event.schema.json` from this ADR)
- 0020 — fact-vector v2 migration (concrete prior example of an additive v2 evolution)
- 0021 — validator hardening (sanitize-check rule extensions consume the new fields)

## Proposal claims

- C-SCHEMA-V2 — schema v2 additive extension (new claim, anchored by this ADR + the v1↔v2 compatibility test).
- C-NEW-HG / C-NEW-IC / C-NEW-CS / C-NEW-DP / C-NEW-CD — discovery-engine claim families depend on this schema extension for record emission.
- C-TECH-3 — evidence schema (now 16 node families + 17+ edge types) preserved across the additive migration.
- C-EVAL-1 — public-package verification continues to depend on schema stability; this ADR's regression test enforces it.
