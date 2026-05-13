"""PolyDiff qr family (Engine 1, T-M2.5).

Per Asemarefactor.md §"Engine 1: PolyDiff Extended" qr family —
"NEW — ZXing / ZBar / Apple Vision / iOS detector". The qr family
covers QR-symbol decoding by ZXing, ZBar, Apple Vision (macOS only),
and the iOS Camera URL handler so disagreements among them surface
URL-in-QR phishing, structured-append misordering, charset confusion,
and kanji-mode ambiguity classes:

  * zxing_cli                (python; subprocess wrapper for ZXing CLI)
  * zbar_cli                 (python; subprocess wrapper for ZBar CLI)
  * apple_vision_stub        (python; stub — binary_missing on non-macOS)
  * ios_detector_stub        (python; stub — binary_missing always)

Wrappers live under `wrappers/`; each exposes a `run(witness_bytes,
input_id) -> dict` callable. When the underlying decoder binary is
absent in the current environment (no ZXing/ZBar in the devcontainer,
no Apple/iOS toolchain on Linux), `run()` returns a
`_crash_envelope`-equivalent fact-vector with `binary_missing=true` and
`decode_outcome.status='parse_error'`. This keeps the diff engine
output deterministic across environments.

The fact-vector axes (per T-M2.5 spec, 10 axes):

    detected_text             string|null
    ecc_level                 enum[L,M,Q,H]|null
    version                   integer|null (1-40)
    mode                      enum[numeric,alphanumeric,byte,kanji]|null
    encoding_charset          string|null
    structured_append_index   integer|null
    structured_append_total   integer|null
    fnc1_present              boolean|null
    parser_warnings           [string]
    decode_outcome            {status: enum, bytes_out: int}

Schema: schema/fact-vector-qr.schema.json (sibling to the URL / image /
opengraph / deeplink family fact-vector schemas).

Corpus: polydiff/families/qr/regression/corpus.json (manifests pinned
by SHA-256 only; no payload bytes in this repo). The anchored cases
are: iOS Camera URL handler vs ZXing URL extraction divergence,
structured-append misorder, ECI-tagged UTF-8 vs default Shift-JIS, and
kanji-mode ambiguity.
"""

from __future__ import annotations

from pathlib import Path


def family_yaml_path() -> Path:
    """Return absolute path to family.yaml — the declarative manifest."""
    return Path(__file__).resolve().parent / "family.yaml"


def corpus_path() -> Path:
    """Return absolute path to the qr-family regression corpus.json."""
    return _repo_root() / "polydiff" / "families" / "qr" / "regression" / "corpus.json"


def index_path() -> Path:
    """Return absolute path to the qr-family rediscovery INDEX.json."""
    return _repo_root() / "polydiff" / "families" / "qr" / "regression" / "INDEX.json"


def _repo_root() -> Path:
    # aegisgraph/polydiff/families/qr/__init__.py -> parents[4] = repo root
    return Path(__file__).resolve().parents[4]


__all__ = ["family_yaml_path", "corpus_path", "index_path"]
