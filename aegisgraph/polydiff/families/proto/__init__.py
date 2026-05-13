"""PolyDiff proto family (Engine 1, T-M2.6).

Per Asemarefactor.md §"Engine 1: PolyDiff Extended" proto family —
"NEW — protobuf / FlatBuffer / msgpack". The proto family covers
binary serialization format decoding by protoc + google-protobuf
(python), flatc (FlatBuffer compiler), msgpack (python parser), and a
gogo-protobuf-faster stub so disagreements among them surface unknown
field handling, oneof ambiguity, FlatBuffer offset overflow, and
msgpack ext-type collision classes:

  * protoc_python              (python; subprocess wrapper for protoc +
                                google protobuf python decoder)
  * flatc_runner               (python; subprocess wrapper for flatc)
  * msgpack_python             (python; subprocess wrapper for the
                                msgpack python parser)
  * protoc_gogofaster_stub     (python; stub — binary_missing always)

Wrappers live under `wrappers/`; each exposes a `run(witness_bytes,
input_id) -> dict` callable. When the underlying decoder binary is
absent in the current environment (no protoc/flatc/msgpack in the
devcontainer, no gogo-protobuf), `run()` returns a
`_crash_envelope`-equivalent fact-vector with `binary_missing=true` and
`decode_outcome.status='parse_error'`. This keeps the diff engine
output deterministic across environments.

The fact-vector axes (per T-M2.6 spec, 9 axes):

    format_kind               enum[protobuf,flatbuffer,msgpack]
    declared_schema_version   string|null
    message_type_name         string|null
    field_count               integer|null
    field_unknown_count       integer|null
    oneof_active_field        string|null
    decoded_field_summary     object|null
    parser_warnings           [string]
    decode_outcome            {status: enum, bytes_out: int}

Schema: schema/fact-vector-proto.schema.json (sibling to the URL /
image / opengraph / deeplink / qr family fact-vector schemas).

Corpus: polydiff/families/proto/regression/corpus.json (manifests
pinned by SHA-256 only; no payload bytes in this repo). The anchored
cases are: gogo-protobuf vs google-protobuf unknown-field handling,
oneof ambiguity, FlatBuffer offset overflow, and msgpack ext-type
collision.
"""

from __future__ import annotations

from pathlib import Path


def family_yaml_path() -> Path:
    """Return absolute path to family.yaml — the declarative manifest."""
    return Path(__file__).resolve().parent / "family.yaml"


def corpus_path() -> Path:
    """Return absolute path to the proto-family regression corpus.json."""
    return _repo_root() / "polydiff" / "families" / "proto" / "regression" / "corpus.json"


def index_path() -> Path:
    """Return absolute path to the proto-family rediscovery INDEX.json."""
    return _repo_root() / "polydiff" / "families" / "proto" / "regression" / "INDEX.json"


def _repo_root() -> Path:
    # aegisgraph/polydiff/families/proto/__init__.py -> parents[4] = repo root
    return Path(__file__).resolve().parents[4]


__all__ = ["family_yaml_path", "corpus_path", "index_path"]
