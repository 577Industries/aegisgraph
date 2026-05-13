# PolyDiff proto-family regression corpus

This directory holds **hash-pin files only** for proto-family anchored
witnesses. Per Asemarefactor.md §"Engine 1: PolyDiff Extended" and the
schema additive-only policy (ADR-0010), witness BYTES never appear in
this repository.

## Layout

| File | What it pins |
|---|---|
| `anchor_proto_unknown_field_handling.sha256` | A protobuf wire payload with extra fields not declared in the decoder's schema. google-protobuf and gogo-protobuf historically diverge on the field_unknown_count reported. Exercises the **field_unknown_count divergence -> MEDIUM-HIGH** triage rule (unknown-field-handling bug class). |
| `anchor_proto_oneof_ambiguity.sha256` | A protobuf wire payload where the same bytes resolve to different active fields in a `oneof` group depending on decoder interpretation. Exercises the **oneof_active_field divergence -> MEDIUM-HIGH** triage rule (oneof-ambiguity class). |
| `anchor_flatbuffer_offset_overflow.sha256` | A FlatBuffer payload with an offset value that exceeds the buffer length. flatc with bounds-checking rejects it (parse_error) while a permissive decoder silently decodes garbage memory. Exercises the **decode_outcome divergence (ok + parse_error) -> HIGH** triage rule (flatbuffer-offset-overflow bug class). |
| `anchor_msgpack_ext_type_collision.sha256` | An msgpack payload using an ext-type tag that two decoders interpret differently — e.g. as a timestamp vs raw bytes. Exercises the **decoded_field_summary divergence -> MEDIUM** triage rule (msgpack-ext-type-collision class). |

The canonical manifest with sizes, expected fact-vector diffs, and triage
expectations is `../corpus.json`. The rediscovery manifest with SHA pins
(Asemarefactor.md lines 35-37 contract) is `../INDEX.json`.

## Witness bytes provenance

The synthetic-bug witnesses are vendored privately at
`reprochain/corpora-private/proto_*.pb`, `flatbuffer_*.fbs`,
`msgpack_*.msgpack`. That directory is engineering-side only and
excluded from every public release through
`validator/sanitize_check.py` Rule 5 + the existing `EXCLUSIONS.md`
allowlist.

The proto family **never reads bytes** from the corpus in the
public/engineering pipeline. The diff engine operates on
`(witness_sha256, witness_size_bytes)` and per-implementation fact
vectors only.

## Public citation guidance

The gogo-protobuf vs google-protobuf unknown-field-handling
divergence has been documented in protobuf ecosystem discussions and
in protobuf-vs-gogo migration guides. The oneof-ambiguity class is
documented in the protobuf spec's "oneof semantics" annex. The
FlatBuffer offset-overflow class is documented in FlatBuffer security
research. The msgpack ext-type-collision class is documented in
msgpack-ecosystem cross-implementation research. All four anchored
cases here are synthetic representations of our own design; specific
public references for the historical bug variants are retained
engineering-private to avoid amplifying any still-exploitable
specifics.

## Network constraint

Proto-family wrappers MUST NOT fetch URLs over the network. The
binary payload bytes are supplied to each wrapper subprocess on
stdin; nothing in this directory or in the wrapper code is permitted
to make outbound HTTP requests. This invariant is checked by the
wrapper subprocess contract tests.
