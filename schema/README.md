# AegisGraph Schemas (`schema/`)

JSON Schema 2020-12 contracts for every evidence record AegisGraph emits. The schemas are the load-bearing API between the five engineering streams (reprochain-proof, polydiff-core, real-extraction, smabench-harness, validator-export) and the validator + traceability matrix.

## Versioning policy

Schema files in this directory evolve **additively only**. The policy is documented in **ADR 0010** (`docs/decision-log/0010-schema-additive-only.md`). The fact-vector v2 migration (`fact-vector.schema.v2.proposed.json`) is the canonical concrete example; see **ADR 0020**.

The five rules in summary:

1. **Additive fields must be nullable or have `default`.** New properties on a v1 schema MUST be either `"type": ["X", "null"]`, have `"default": null`, or be absent from the `required` array. Every existing record must still validate against the updated schema.
2. **Removing a property is a breaking change.** Even if no record currently sets the field. Deletion requires a v2 schema.
3. **Tightening a `pattern`, `enum`, `minLength`, `minimum`, etc. is a breaking change.** Loosening (extending an enum, lowering minLength) is additive.
4. **Renaming is forbidden.** Add the new name as an optional alias; deprecate the old name in an ADR; remove only when issuing v2.
5. **`additionalProperties: false` is intentional.** New fields land in the schema first, then in the emitter.

## v1 schemas (current canonical)

| File | Purpose | Owner stream |
|---|---|---|
| `evidence.schema.json` | Top-level evidence record (id, target, path_class, nodes, edges, score_vector, claim_state, validation_task, evidence_refs, recommendation_refs, limitations, provenance, safety_flags) | integration / shared |
| `fact-vector.schema.json` | PolyDiff URL fact vector (v1, ~9 axes — the smoke baseline) | polydiff-core |
| `finding.schema.json` | Per-finding record (security-relevance tag + disagreement / disclosure_status / claim_state lifecycle) | polydiff-core / reprochain-proof |
| `hash-chain.schema.json` | Per-record hash-chain link (previous_hash, content_hash, signature) | integration / shared |
| `recommendation.schema.json` | Recommendation contract (id, category, graph-refs, evidence-refs, source-anchors, implementation-hint, expected-effect, residual-risk, effort-estimate, standards-mapping-caveat, derived_from_finding) | shared |
| `tool-output.schema.json` | Tool-output document (tool_output_type, safety_posture, scan output) | real-extraction / smabench-harness |

## v2 proposals (additive successors)

| File | Status | Migration governance |
|---|---|---|
| `fact-vector.schema.v2.proposed.json` | Proposed (ADR 0020) | Polydiff-core proposes; integration ratifies; validator-export accepts both during the migration window |

The `.proposed.json` filename suffix keeps the file visible but excluded from the default validator pickup until promotion. Promotion = rename to `fact-vector.schema.v2.json` after every downstream consumer has been updated and the validator-export stream has confirmed v1 + v2 dual-acceptance is no longer needed. The integration stream merges this rename only after confirming no v1 emitters remain.

## Inheritance hierarchy

```
evidence.schema.json
    ├── nodes[]              -> per-node typed record (entry / sink / intermediate)
    ├── evidence_refs[]      -> tool-output.schema.json (one per tool invocation)
    ├── score_vector         -> sum check (10 dimensions sum to 100)
    ├── recommendation_refs  -> recommendation.schema.json (per-rec id)
    └── provenance           -> hash-chain.schema.json (per-record link)

finding.schema.json
    ├── from_disagreement   -> fact-vector.schema.json (paired vectors v1)
    │                           OR fact-vector.schema.v2.proposed.json (v2)
    └── reachability        -> evidence.schema.json (back-pointer; transitive)
```

A record can reference both v1 and v2 fact-vectors simultaneously during the v2 migration window. The validator (per ADR 0021) accepts both shapes; downstream tooling reads the schema version off the record's `schema_version` field.

## Migration governance

Schema deltas go through the **schema-delta-via-PR-plus-ADR contract** documented in `docs/operating-procedures.md` §2:

1. Fork to `<name>.schema.v2.proposed.json` if the change is breaking. Otherwise add additively to the existing file.
2. Open an ADR under `docs/decision-log/` numbered consecutively. Include sections: Decision, Rationale, Status, Affected streams, Migration plan.
3. Submit ADR + schema change in the SAME PR. The schema is never merged without its ADR.
4. Integration owner runs `make test` (verifies all schemas still pass `Draft202012Validator.check_schema()`) and `make validate` (verifies no record regresses) before accepting the merge.
5. Promotion (`.proposed.json` → final filename) is a separate PR after all emitters + validators are dual-write capable.

## Why this matters

Every reproduce produces evidence records that hash-chain back to their inputs. A breaking schema change in any file silently invalidates every existing record. The DARPA/ASEMA submission manifest hashes the records; an invalidation of in-flight records during the submission window is a non-recoverable timing failure.

Additive-only makes the schema a versioned API rather than a moving target, lets parallel streams ship without coordinating timestamps, and protects the hash-chain guarantee that `record_hash(N+1)` only changes when *content* changes.

## Tests

`tests/test_schema_validation.py` enforces:

- Each schema is a valid Draft 2020-12 schema (`test_each_schema_file_is_valid_draft_2020_12`).
- The 6 baseline schemas remain present (`test_at_least_six_schemas_present`). Silently deleting a schema fails-loud.
- `aegisgraph.validation.validate_repo` runs every emitted record through `validate_against_schema` against the on-disk schema. Any non-additive change shows up as record-level validation failures the moment the v1 record is re-emitted on a subsequent reproduce.

Run `python3 -m pytest tests/test_schema_validation.py -q` to verify the schema layer in isolation.
