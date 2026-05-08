# 0010 Schema Additive-Only Migration Policy

Status: accepted, integration stream owns enforcement.

## Decision

JSON Schema files in `/schema/` evolve **additively only**. The v1.0 evidence
schema is the contract every evidence record across the platform must
continue to satisfy. Breaking changes are forbidden under the existing
filename; they require a **new versioned schema file** (`schema/<name>.schema.v2.proposed.json`)
and a fresh ADR before any code starts emitting v2-only fields.

## Rules

1. **Additive fields must be nullable or have `default`.** A new property
   added to a v1.0 schema MUST have either `"type": ["X", "null"]` (or list
   `null` in the type union), `"default": null`, or be absent from the
   `required` array. This keeps every existing v1.0 record valid against
   the updated schema. Stream owners must include a unit test that an
   unmodified record from before the change still validates.

2. **Removing a property is a breaking change.** Deletion is never additive,
   even if no record currently sets the field. Removal requires a v2 schema.

3. **Tightening a `pattern`, `enum`, `minLength`, `minimum`, etc. is a
   breaking change.** A loosening (extending an enum, lowering minLength) is
   additive.

4. **Renaming is forbidden.** Add the new name as an optional alias; deprecate
   the old name in an ADR and remove only when issuing v2.

5. **`additionalProperties: false` is intentional.** Streams cannot bypass
   the contract by smuggling extra fields. New fields are added to the
   schema first, then to the emitter.

## v2 process (when forced)

1. Open an ADR (next free number under `docs/decision-log/`).
2. Add the new schema file as `schema/<name>.schema.v2.proposed.json`.
   Filename suffix `.proposed.json` keeps it visible but excluded from the
   default validator pickup until promotion.
3. Add a follower ADR documenting promotion criteria + rollout order.
4. Ship the v2 emitter under a feature flag.
5. After every downstream consumer has been updated, rename
   `<name>.schema.v2.proposed.json` -> `<name>.schema.v2.json` and delete
   `.proposed.json`. The integration stream merges this rename only after
   confirming no v1 emitters remain.

## Enforcement

- `tests/test_schema_validation.py::test_each_schema_file_is_valid_draft_2020_12`
  rejects any syntactically broken schema.
- `tests/test_schema_validation.py::test_at_least_six_schemas_present`
  fails-loud if a baseline schema is silently deleted.
- `aegisgraph.validation.validate_repo` runs every emitted record through
  `validate_evidence_record`, which calls `validate_against_schema` against
  the on-disk schema. Any non-additive change shows up as record-level
  validation failures the moment the v1 record is re-emitted on a
  subsequent reproduce.

## Why

ReproChain, polydiff, smabench, extraction, and validator-export all emit
evidence records on every reproduce. A breaking change in any schema
silently invalidates every existing record. The DARPA/ASEMA submission
manifest hashes the records; an invalidation of in-flight records during
the submission window is a non-recoverable timing failure. Additive-only
makes the schema a versioned API rather than a moving target, lets parallel
streams ship without coordinating timestamps, and protects the hash-chain
guarantee that record_hash(N+1) only changes when *content* changes.

## Out of scope

- Migrating fact-vector to v2 is **not** done by the integration stream.
  The polydiff-core stream owns proposing v2 if URL-parser disagreement
  data demands new fields. They write the proposed file + ADR; integration
  reviews and accepts.
- Schemas live under `/schema/` only. Per-stream draft schemas living
  elsewhere are not subject to this policy until promoted.

## Related

- 0005 — validator migration (the v0.2 → v1.0 baseline this policy locks down going forward)
- 0020 — fact-vector v2 migration (concrete additive v2 schema example governed by this policy)
- 0021 — validator hardening (the validator that enforces the schema-validation rule above)

## Proposal claims

- C-TECH-3 — evidence schema (9 node families + 11 edge types) preserved across migrations.
- C-EVAL-1 — public-package verification depends on schema stability.
- C-EVAL-3 — reproducibility from target + commit + evidence refs depends on stable schema contracts.
