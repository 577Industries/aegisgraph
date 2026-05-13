"""family.yaml structural / contract tests for the opengraph family.

Per Asemarefactor.md §"Engine 1: PolyDiff Extended" and mirroring the
image-family family.yaml shape (T-M2.1), each PolyDiff family declares:

  1. `family` — string identifier (here, "opengraph").
  2. `implementations` — list of {id, bindings, wrapper} entries; one per
     parser implementation. For opengraph we ship:
       - facebook_og           (python; OG parser)
       - twitter_card          (python; Twitter Card meta-tag parser)
       - oembed                (python; oEmbed JSON/XML parser)
       - beautifulsoup_fallback (python; html5lib + bs4 generic parser)
  3. `fact_vector_schema.axes` — list naming the per-family axes the diff
     engine compares. For opengraph (11 axes):
       og_title, og_image, og_type, og_url, og_video,
       twitter_card_type, twitter_image, oembed_type,
       canonical_url, parser_warnings, decode_outcome.

The file lives at
  aegisgraph/polydiff/families/opengraph/family.yaml
and is the single source of truth for opengraph-family wrapper discovery,
diff-engine axes, and reachability mapping. Tests pin the *shape* so a
refactor doesn't silently drop an axis or wrapper.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisgraph.io import repo_root


FAMILY_YAML_PATH = (
    repo_root() / "aegisgraph" / "polydiff" / "families" / "opengraph" / "family.yaml"
)

EXPECTED_IMPLEMENTATIONS = {
    "facebook_og": "python",
    "twitter_card": "python",
    "oembed": "python",
    "beautifulsoup_fallback": "python",
}

EXPECTED_AXES = {
    "og_title",
    "og_image",
    "og_type",
    "og_url",
    "og_video",
    "twitter_card_type",
    "twitter_image",
    "oembed_type",
    "canonical_url",
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


def test_family_field_is_opengraph() -> None:
    data = _load_yaml()
    assert data.get("family") == "opengraph", (
        f"family field must equal 'opengraph'; got {data.get('family')!r}"
    )


def test_all_four_implementations_declared() -> None:
    data = _load_yaml()
    impls = data.get("implementations") or []
    ids = {entry.get("id") for entry in impls if isinstance(entry, dict)}
    assert ids == set(EXPECTED_IMPLEMENTATIONS.keys()), (
        f"opengraph family must declare exactly {sorted(EXPECTED_IMPLEMENTATIONS)}; "
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
        f"opengraph fact_vector axes must equal {sorted(EXPECTED_AXES)}; "
        f"got {sorted(axes_seen)}"
    )


def test_reachability_block_present() -> None:
    """Opengraph metadata is consumed by link-preview generators; the
    reachability block names at least one target codepath (signal_android,
    element_x_android, or a link-preview-generator class) so an emitted
    AG-DIS-OG-* record can be correlated to a consuming site."""
    data = _load_yaml()
    reachability = data.get("reachability") or {}
    assert reachability, (
        "opengraph family.yaml must declare a non-empty reachability block"
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
