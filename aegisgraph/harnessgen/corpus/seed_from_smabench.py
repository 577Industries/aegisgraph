"""Seed a libFuzzer corpus from SMABench inputs.

`seed_corpus(src, dest, format_filter)` walks `src` recursively, keeps
files whose suffix matches `format_filter` (e.g. "webp" -> *.webp), dedupes
by content SHA-256, and writes the unique bytes into `dest/<sha256>` —
the libFuzzer-standard naming where each corpus entry is named for its
own hash.

Why dedup? SMABench corpora are assembled from public sources that
often overlap; serving the same bytes twice to libFuzzer is wasted
compute. The dedup also stabilizes the corpus across reruns: a new
SMABench source dropping in a copy of an existing file doesn't change
the on-disk corpus state.

This module does NOT fetch corpora from the network; that's an upstream
responsibility (SMABench itself). It does NOT validate that the bytes
are syntactically valid in their declared format — libFuzzer's job is to
explore from any starting point.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SeedingResult:
    """Outcome counters for a seeding pass.

    * scanned : files that matched the format_filter and were inspected
    * written : unique entries written to dest
    * deduped : duplicates skipped (content already in dest)
    * skipped : files that did NOT match the format_filter
    """

    scanned: int
    written: int
    deduped: int
    skipped: int


def _content_hash(path: Path) -> str:
    """SHA-256 hex of file content. Streamed so we don't load big files."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _matches_format(path: Path, format_filter: str | None) -> bool:
    """Return True iff `path` should be considered a seed candidate.

    The filter is suffix-matched without the leading dot: "webp" matches
    `*.webp`. An empty filter matches everything (used for raw "give me
    every file" corpora — uncommon).
    """
    if not format_filter:
        return True
    return path.suffix.lower() == f".{format_filter.lower()}"


def seed_corpus(
    src: Path,
    dest: Path,
    format_filter: str | None = None,
) -> SeedingResult:
    """Walk `src`, dedup by content, write hash-named files to `dest`.

    Returns a SeedingResult with per-bucket counts.
    """
    src = Path(src)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)

    seen: set[str] = set()
    # Pre-populate `seen` with anything already in dest so successive runs
    # are idempotent — re-running this on the same (src, dest) pair won't
    # mark already-written files as duplicates of themselves.
    for entry in dest.iterdir():
        if entry.is_file() and len(entry.name) == 64:
            seen.add(entry.name)

    scanned = 0
    written = 0
    deduped = 0
    skipped = 0

    if not src.is_dir():
        return SeedingResult(scanned=0, written=0, deduped=0, skipped=0)

    for path in sorted(src.rglob("*")):
        if not path.is_file():
            continue
        if not _matches_format(path, format_filter):
            skipped += 1
            continue
        scanned += 1
        digest = _content_hash(path)
        if digest in seen:
            deduped += 1
            continue
        seen.add(digest)
        target = dest / digest
        target.write_bytes(path.read_bytes())
        written += 1

    return SeedingResult(
        scanned=scanned, written=written, deduped=deduped, skipped=skipped
    )


__all__ = ["SeedingResult", "seed_corpus"]
