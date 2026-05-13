"""PolyDiff image family (Engine 1, T-M2.1).

Per Asemarefactor.md §"Engine 1: PolyDiff Extended" (lines 42-92), the
image family covers:

  * Native parsers: libwebp / libavif / libheif (via subprocess CLI wrappers)
  * JVM parsers:    glide_bitmap / coil_decoder (via subprocess JVM runners)

Wrappers live under `wrappers/`; each exposes a `run(witness_bytes, input_id) ->
dict` callable. When the underlying binary is absent (e.g. CI without the
native libs installed), `run()` returns a `_crash_envelope`-equivalent
fact-vector with `binary_missing=true` and `decode_outcome.status=crash`.
This keeps the diff engine output deterministic across environments.

The fact-vector axes (Asemarefactor.md lines 63-77):

    dimensions          {width, height}
    color_space         {profile, depth}
    alpha_premultiplied bool
    frame_count         int
    first_pixel_rgba    {r, g, b, a}
    decode_outcome      {status: enum, bytes_out: int}
    parser_warnings     [string]

Schema: schema/fact-vector-image.schema.json (sibling to the URL family
fact-vector schema).

Corpus: polydiff/families/image/regression/corpus.json (manifests pinned
by SHA-256 only; no payload bytes in this repo). The CVE-2023-4863
witness is the ground-truth anchor; payload bytes are vendored at
reprochain/corpora-private/ engineering-side only.
"""

from __future__ import annotations

from pathlib import Path


def family_yaml_path() -> Path:
    """Return absolute path to family.yaml — the declarative manifest."""
    return Path(__file__).resolve().parent / "family.yaml"


def corpus_path() -> Path:
    """Return absolute path to the image-family regression corpus.json.

    The corpus lives outside the aegisgraph/ python package tree (it is
    operator-editable data, not code); we expose its canonical location
    here so callers don't hard-code the path.
    """
    return _repo_root() / "polydiff" / "families" / "image" / "regression" / "corpus.json"


def index_path() -> Path:
    """Return absolute path to the image-family regression INDEX.json
    (rediscovery manifest with SHA pins per Asemarefactor.md lines 35-37).
    """
    return _repo_root() / "polydiff" / "families" / "image" / "regression" / "INDEX.json"


def _repo_root() -> Path:
    # aegisgraph/polydiff/families/image/__init__.py -> parents[4] = repo root
    return Path(__file__).resolve().parents[4]


__all__ = ["family_yaml_path", "corpus_path", "index_path"]
