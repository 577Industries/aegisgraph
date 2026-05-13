"""family.yaml structural / contract tests for the image family.

Per Asemarefactor.md lines 42-92 (canonical example), each PolyDiff family
declares three things in family.yaml:

  1. `family` — string identifier (here, "image").
  2. `implementations` — list of {id, bindings, wrapper} entries; one per
     parser implementation. For image we ship:
       - libwebp        (native)
       - libavif        (native)
       - libheif        (native)
       - glide_bitmap   (jvm)
       - coil_decoder   (jvm)
  3. `fact_vector_schema.axes` — list naming the per-family axes the diff
     engine compares. For image (Asemarefactor.md lines 63-77):
       dimensions, color_space, alpha_premultiplied, frame_count,
       first_pixel_rgba, decode_outcome, parser_warnings.
  4. `reachability` — per-target codepath mapping for each path_class.

The file lives at
  aegisgraph/polydiff/families/image/family.yaml
and is the single source of truth for image-family wrapper discovery,
diff-engine axes, and reachability mapping. Tests here pin the *shape* of
that file so a refactor doesn't silently drop an axis or wrapper.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisgraph.io import repo_root


FAMILY_YAML_PATH = (
    repo_root() / "aegisgraph" / "polydiff" / "families" / "image" / "family.yaml"
)

EXPECTED_IMPLEMENTATIONS = {
    "libwebp": "native",
    "libavif": "native",
    "libheif": "native",
    "glide_bitmap": "jvm",
    "coil_decoder": "jvm",
}

EXPECTED_AXES = {
    "dimensions",
    "color_space",
    "alpha_premultiplied",
    "frame_count",
    "first_pixel_rgba",
    "decode_outcome",
    "parser_warnings",
}


def _load_yaml() -> dict:
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover - yaml is in stdlib of devcontainer
        pytest.skip("PyYAML not available in this environment")
    with FAMILY_YAML_PATH.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_family_yaml_file_exists() -> None:
    assert FAMILY_YAML_PATH.is_file(), f"missing {FAMILY_YAML_PATH}"


def test_family_field_is_image() -> None:
    data = _load_yaml()
    assert data.get("family") == "image", (
        f"family field must equal 'image'; got {data.get('family')!r}"
    )


def test_all_five_implementations_declared() -> None:
    data = _load_yaml()
    impls = data.get("implementations") or []
    ids = {entry.get("id") for entry in impls if isinstance(entry, dict)}
    assert ids == set(EXPECTED_IMPLEMENTATIONS.keys()), (
        f"image family must declare exactly {sorted(EXPECTED_IMPLEMENTATIONS)}; "
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
        # Wrapper paths are documented relative to the family root. We just
        # require they reference the `wrappers/` subdirectory.
        assert "wrappers/" in str(wrapper_ref), (
            f"wrapper {wrapper_ref!r} for {entry.get('id')} must live under wrappers/"
        )


def test_fact_vector_axes_match_asemarefactor() -> None:
    data = _load_yaml()
    fvs = data.get("fact_vector_schema") or {}
    axes_decl = fvs.get("axes") or []
    # axes may be either a list of strings or a list of single-key dicts
    # (per the YAML in Asemarefactor.md lines 64-71 which uses inline
    # mappings). We accept either shape.
    axes_seen: set[str] = set()
    for entry in axes_decl:
        if isinstance(entry, str):
            axes_seen.add(entry)
        elif isinstance(entry, dict):
            # The dict has a single key naming the axis.
            axes_seen.update(entry.keys())
    assert axes_seen == EXPECTED_AXES, (
        f"image fact_vector axes must equal {sorted(EXPECTED_AXES)}; "
        f"got {sorted(axes_seen)}"
    )


def test_reachability_block_present_for_signal_and_element_x() -> None:
    data = _load_yaml()
    reachability = data.get("reachability") or {}
    # Asemarefactor.md lines 73-82 declares signal_android + element_x_android
    # entries pointing media_handler entry/sink.
    assert "signal_android" in reachability, (
        "reachability.signal_android missing — required per Asemarefactor.md lines 74-77"
    )
    assert "element_x_android" in reachability, (
        "reachability.element_x_android missing — required per Asemarefactor.md lines 78-81"
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
