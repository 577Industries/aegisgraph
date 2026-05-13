"""PolyDiff deeplink family (Engine 1, T-M2.4).

Per Asemarefactor.md §"Engine 1: PolyDiff Extended" deeplink family —
"NEW — Android intent URI + iOS universal link". The deeplink family
covers Android `intent://` URI parsing, iOS universal links / custom
schemes, and a WHATWG-URL generic cross-check so disagreements among
them surface implicit-export, origin-confusion, open-redirect, and
path-traversal classes:

  * android_intent_uri       (python; mirrors Android Intent.parseUri)
  * ios_universal_link       (python; mirrors NSURL/NSURLComponents)
  * web_url_fallback         (python; generic WHATWG-URL cross-check)
  * custom_scheme_parser     (python; proprietary scheme handling, e.g.
                              sgnl://, signal://)

Wrappers live under `wrappers/`; each exposes a `run(witness_bytes,
input_id) -> dict` callable. When the underlying parser package is
absent in the current environment (no Android/iOS toolchain in the
devcontainer is expected), `run()` returns a `_crash_envelope`-
equivalent fact-vector with `binary_missing=true` and
`decode_outcome.status='parse_error'`. This keeps the diff engine
output deterministic across environments.

The fact-vector axes (per T-M2.4 spec, 10 axes):

    scheme                string
    host                  string|null
    path                  string|null
    query_params          object|null
    fragment_action       string|null
    declared_permissions  [string]
    intent_action         string|null
    intent_category       [string]|null
    parser_warnings       [string]
    decode_outcome        {status: enum, bytes_out: int}

Schema: schema/fact-vector-deeplink.schema.json (sibling to the URL /
image / opengraph family fact-vector schemas).

Corpus: polydiff/families/deeplink/regression/corpus.json (manifests
pinned by SHA-256 only; no payload bytes in this repo). The anchored
cases are: Android intent implicit-export, iOS universal link
origin-confusion, deeplink open-redirect, and a custom-scheme
traversal divergence.
"""

from __future__ import annotations

from pathlib import Path


def family_yaml_path() -> Path:
    """Return absolute path to family.yaml — the declarative manifest."""
    return Path(__file__).resolve().parent / "family.yaml"


def corpus_path() -> Path:
    """Return absolute path to the deeplink-family regression corpus.json."""
    return _repo_root() / "polydiff" / "families" / "deeplink" / "regression" / "corpus.json"


def index_path() -> Path:
    """Return absolute path to the deeplink-family rediscovery INDEX.json."""
    return _repo_root() / "polydiff" / "families" / "deeplink" / "regression" / "INDEX.json"


def _repo_root() -> Path:
    # aegisgraph/polydiff/families/deeplink/__init__.py -> parents[4] = repo root
    return Path(__file__).resolve().parents[4]


__all__ = ["family_yaml_path", "corpus_path", "index_path"]
