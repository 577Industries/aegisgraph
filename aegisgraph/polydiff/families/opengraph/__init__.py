"""PolyDiff opengraph family (Engine 1, T-M2.2).

Per Asemarefactor.md §"Engine 1: PolyDiff Extended" (proposed module
layout lines 22-37 lists opengraph/ as one of the five new families).
The opengraph family covers OG / Twitter Card / oEmbed / canonical-URL
metadata parsers and surfaces disagreements among:

  * facebook_og              (python OG parser, simulating FB crawler)
  * twitter_card             (python Twitter Card meta-tag parser)
  * oembed                   (python oEmbed JSON/XML response parser)
  * beautifulsoup_fallback   (html5lib + bs4 generic cross-check parser)

Wrappers live under `wrappers/`; each exposes a `run(witness_bytes,
input_id) -> dict` callable. When the underlying parser package is
absent in the current environment, `run()` returns a
`_crash_envelope`-equivalent fact-vector with `binary_missing=true` and
`decode_outcome.status=crash`. This keeps the diff engine output
deterministic across environments.

The fact-vector axes (per T-M2.2 spec, 11 axes):

    og_title              string|null
    og_image              string|null
    og_type               string|null
    og_url                string|null
    og_video              string|null
    twitter_card_type     string|null
    twitter_image         string|null
    oembed_type           string|null
    canonical_url         string|null
    parser_warnings       [string]
    decode_outcome        {status: enum, bytes_out: int}

Schema: schema/fact-vector-opengraph.schema.json (sibling to the URL
family fact-vector schema and the image family fact-vector schema).

Corpus: polydiff/families/opengraph/regression/corpus.json (manifests
pinned by SHA-256 only; no payload bytes in this repo). The anchored
historical bugs are: Facebook crawler relative-URL quirk (~2018),
Twitter Card `player` XSS, oEmbed provider origin confusion, and a
synthetic meta tag quote-escape divergence.
"""

from __future__ import annotations

from pathlib import Path


def family_yaml_path() -> Path:
    """Return absolute path to family.yaml — the declarative manifest."""
    return Path(__file__).resolve().parent / "family.yaml"


def corpus_path() -> Path:
    """Return absolute path to the opengraph-family regression corpus.json."""
    return _repo_root() / "polydiff" / "families" / "opengraph" / "regression" / "corpus.json"


def index_path() -> Path:
    """Return absolute path to the opengraph-family rediscovery INDEX.json."""
    return _repo_root() / "polydiff" / "families" / "opengraph" / "regression" / "INDEX.json"


def _repo_root() -> Path:
    # aegisgraph/polydiff/families/opengraph/__init__.py -> parents[4] = repo root
    return Path(__file__).resolve().parents[4]


__all__ = ["family_yaml_path", "corpus_path", "index_path"]
