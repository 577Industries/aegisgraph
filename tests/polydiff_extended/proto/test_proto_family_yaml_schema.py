"""family.yaml structural / contract tests for the proto family.

Per Asemarefactor.md §"Engine 1: PolyDiff Extended" proto family,
mirroring the deeplink + opengraph + image-family family.yaml shape,
each PolyDiff family declares:

  1. `family` — string identifier (here, "proto").
  2. `implementations` — list of {id, bindings, wrapper} entries; one per
     parser implementation. For proto we ship:
       - protoc_python              (python; subprocess wrapper for
                                     protoc + google protobuf python)
       - flatc_runner               (python; FlatBuffer flatc decoder)
       - msgpack_python             (python; msgpack python parser)
       - protoc_gogofaster_stub     (python; gogo-protobuf stub —
                                     binary_missing always)
  3. `fact_vector_schema.axes` — list naming the per-family axes the diff
     engine compares. For proto (9 axes):
       format_kind, declared_schema_version, message_type_name,
       field_count, field_unknown_count, oneof_active_field,
       decoded_field_summary, parser_warnings, decode_outcome.

The file lives at
  aegisgraph/polydiff/families/proto/family.yaml
and is the single source of truth for proto-family wrapper discovery,
diff-engine axes, and reachability mapping.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisgraph.io import repo_root


FAMILY_YAML_PATH = (
    repo_root() / "aegisgraph" / "polydiff" / "families" / "proto" / "family.yaml"
)

EXPECTED_IMPLEMENTATIONS = {
    "protoc_python": "python",
    "flatc_runner": "python",
    "msgpack_python": "python",
    "protoc_gogofaster_stub": "python",
}

EXPECTED_AXES = {
    "format_kind",
    "declared_schema_version",
    "message_type_name",
    "field_count",
    "field_unknown_count",
    "oneof_active_field",
    "decoded_field_summary",
    "parser_warnings",
    "decode_outcome",
}


def _load_yaml() -> dict:
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover - PyYAML in devcontainer
        pytest.skip("PyYAML not available in this environment")
    with FAMILY_YAML_PATH.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_family_yaml_file_exists() -> None:
    assert FAMILY_YAML_PATH.is_file(), f"missing {FAMILY_YAML_PATH}"


def test_family_field_is_proto() -> None:
    data = _load_yaml()
    assert data.get("family") == "proto", (
        f"family field must equal 'proto'; got {data.get('family')!r}"
    )


def test_all_four_implementations_declared() -> None:
    data = _load_yaml()
    impls = data.get("implementations") or []
    ids = {entry.get("id") for entry in impls if isinstance(entry, dict)}
    assert ids == set(EXPECTED_IMPLEMENTATIONS.keys()), (
        f"proto family must declare exactly {sorted(EXPECTED_IMPLEMENTATIONS)}; "
        f"got {sorted(ids)}"
    )


def test_implementation_bindings_correct() -> None:
    data = _load_yaml()
    impls = {
        entry["id"]: entry
        for entry in data.get("implementations") or []
        if isinstance(entry, dict) and "id" in entry
    }
    for impl_id, expected_binding in EXPECTED_IMPLEMENTATIONS.items():
        entry = impls.get(impl_id)
        assert entry is not None, f"missing entry for {impl_id}"
        assert entry.get("bindings") == expected_binding, (
            f"{impl_id} bindings must be {expected_binding!r}; "
            f"got {entry.get('bindings')!r}"
        )


def test_implementation_wrappers_reference_real_paths() -> None:
    data = _load_yaml()
    impls = data.get("implementations") or []
    for entry in impls:
        wrapper_ref = entry.get("wrapper")
        assert wrapper_ref, f"implementation {entry.get('id')} missing wrapper"
        assert "wrappers/" in str(wrapper_ref), (
            f"wrapper {wrapper_ref!r} for {entry.get('id')} must live under wrappers/"
        )


def test_fact_vector_axes_match_spec() -> None:
    data = _load_yaml()
    fvs = data.get("fact_vector_schema") or {}
    axes_decl = fvs.get("axes") or []
    axes_seen: set[str] = set()
    for entry in axes_decl:
        if isinstance(entry, str):
            axes_seen.add(entry)
        elif isinstance(entry, dict):
            axes_seen.update(entry.keys())
    assert axes_seen == EXPECTED_AXES, (
        f"proto fact_vector axes must equal {sorted(EXPECTED_AXES)}; "
        f"got {sorted(axes_seen)}"
    )


def test_reachability_block_present() -> None:
    """Serialized message payloads are consumed by RPC handlers / message
    storage / wire-format processing sites; the reachability block names
    at least one target codepath so an emitted AG-DIS-PROTO-* record can
    be correlated to a consuming site."""
    data = _load_yaml()
    reachability = data.get("reachability") or {}
    assert reachability, (
        "proto family.yaml must declare a non-empty reachability block"
    )
    for target_id, entries in reachability.items():
        assert isinstance(entries, list) and entries, (
            f"reachability.{target_id} must be a non-empty list"
        )
        first = entries[0]
        for key in ("path_class", "entry", "sink"):
            assert key in first, (
                f"reachability.{target_id} entry missing {key!r}"
            )
