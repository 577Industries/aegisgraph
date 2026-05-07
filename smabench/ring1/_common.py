"""Shared helpers for Ring 1 generators.

All generators follow the same contract:

    generate(corpus_dir: Path, *, count: int, seed: int) -> dict

The returned dict is the corpus metadata that gets serialized as
`corpus.metadata.json` in the corpus directory. Items themselves are
written as `<sha8>.<ext>` filenames so collisions surface as an
explicit error (rather than silently overwriting). Determinism is the
load-bearing property: two invocations with the same (count, seed)
must yield byte-identical files AND byte-identical metadata.

We deliberately avoid `os.urandom`, time-derived RNG, or unsorted dict
iteration — every place that needs randomness uses a `random.Random`
instance threaded from the seed, and every place that emits a list
sorts before serialization.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class CorpusItem:
    """One generated item plus the metadata fields kept in the manifest.

    `payload` is the byte-stable serialization of the item. `category`
    is a free-form label (e.g. "userinfo-percent-encoded", "qr-valid-signal")
    that downstream test code can group on. `extra` holds any
    generator-specific JSON-serializable hint (parser axis under test,
    expected behavior, etc.).
    """

    payload: bytes
    extension: str
    category: str
    extra: dict[str, Any]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    @property
    def sha8(self) -> str:
        # Despite the name (kept for the SPEC's documented `<sha8>.txt`
        # filename convention) we use 12 hex chars — birthday-bounded at
        # ~2^24 items, comfortably above any single corpus size. With
        # only 8 we hit ad-hoc collisions in the 10k URL grid.
        return self.sha256[:12]


def write_corpus(
    corpus_dir: Path,
    items: Iterable[CorpusItem],
    *,
    name: str,
    source_policy: str,
    publication_policy: str,
    seed: int,
    count: int,
    generator_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Materialize `items` under `corpus_dir` and emit corpus.metadata.json.

    The metadata file is byte-stable: items are sorted by sha256 before
    serialization and the JSON is canonicalized via `sort_keys=True`.
    A consumer can compute `metadata["sha256"]` (the corpus-wide manifest
    hash) and rely on it as the authoritative byte-stability checksum
    across runs.

    Filename collisions (same sha8 prefix) raise FileExistsError. With
    8 hex chars the birthday bound is ~2^16 items; we generate at most
    ~10k per corpus, so collisions are extremely unlikely but we surface
    them rather than silently masking.

    Existing per-item files are removed before writing to avoid stale
    artefacts when `count` shrinks between runs. corpus.metadata.json
    itself is preserved across this purge so we can compute a clean
    diff later.
    """

    corpus_dir.mkdir(parents=True, exist_ok=True)

    # Purge previous run's per-item files. We touch only files whose name
    # matches our `<sha8>.<ext>` convention; anything else (README,
    # metadata file) is preserved.
    for path in sorted(corpus_dir.iterdir()):
        if path.is_file() and path.name != "corpus.metadata.json":
            stem, dot, _ext = path.name.partition(".")
            if dot and len(stem) == 12 and all(c in "0123456789abcdef" for c in stem):
                path.unlink()
            elif dot and len(stem) == 8 and all(c in "0123456789abcdef" for c in stem):
                # Backward compat: previous runs at 8-char prefix.
                path.unlink()

    written: list[dict[str, Any]] = []
    seen_sha8: set[str] = set()
    items_list = list(items)
    # Sort by sha256 for byte-stable manifest ordering. We do NOT depend
    # on insertion order from the generator — generators are free to emit
    # in whatever order is natural.
    for item in sorted(items_list, key=lambda i: i.sha256):
        if item.sha8 in seen_sha8:
            raise FileExistsError(
                f"sha8 collision in corpus {name!r}: {item.sha8} ({item.category}). "
                "Increase prefix length or reseed."
            )
        seen_sha8.add(item.sha8)
        filename = f"{item.sha8}.{item.extension}"
        (corpus_dir / filename).write_bytes(item.payload)
        written.append(
            {
                "filename": filename,
                "sha256": item.sha256,
                "category": item.category,
                "size_bytes": len(item.payload),
                "extra": item.extra,
            }
        )

    metadata: dict[str, Any] = {
        "name": name,
        "item_count": len(written),
        "source_policy": source_policy,
        "publication_policy": publication_policy,
        "seed": seed,
        "requested_count": count,
        "items": written,
    }
    if generator_extra:
        metadata["generator"] = generator_extra

    # Manifest checksum: hash of canonical JSON of `items`. Matches the
    # behavior of the previous (toy) corpus so downstream `aegisgraph.smabench`
    # can keep using `metadata["sha256"]` as the corpus-wide identity.
    manifest_bytes = json.dumps(written, sort_keys=True, separators=(",", ":")).encode("utf-8")
    metadata["sha256"] = hashlib.sha256(manifest_bytes).hexdigest()

    metadata_path = corpus_dir / "corpus.metadata.json"
    with metadata_path.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2, sort_keys=True)
        handle.write("\n")

    return metadata
