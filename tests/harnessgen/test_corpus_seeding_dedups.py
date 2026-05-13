"""Corpus seeder dedupes SMABench inputs into a fuzz seed corpus.

`seed_from_smabench.seed_corpus(smabench_dir, dest_dir, format_filter=...)`
reads files from SMABench's ring1 corpora directory, dedupes by content
SHA-256, and writes the unique entries into `dest_dir` named by their
SHA-256 (the libFuzzer-standard naming).

Contracts under test:
  * Identical bytes from two source paths produce ONE output file.
  * Filenames are SHA-256 hex (libFuzzer-standard).
  * Files outside the format_filter (e.g. .md, .txt when format_filter is
    'webp') are skipped.
  * Empty source dir -> empty output dir (no errors).
  * Returns a SeedingResult with counts: scanned, written, deduped, skipped.

All filesystem ops use pytest's tmp_path. No live network.
"""

from __future__ import annotations

from pathlib import Path

from aegisgraph.harnessgen.corpus.seed_from_smabench import (
    SeedingResult,
    seed_corpus,
)


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_dedupes_identical_inputs(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dest = tmp_path / "dest"
    _write(src / "a.webp", b"RIFF" + b"\x00" * 30)
    _write(src / "b.webp", b"RIFF" + b"\x00" * 30)  # identical content
    _write(src / "c.webp", b"DIFFERENT" + b"\x00" * 30)

    result = seed_corpus(src, dest, format_filter="webp")
    assert isinstance(result, SeedingResult)
    written = list(dest.iterdir())
    assert len(written) == 2  # one of the dups was skipped
    assert result.written == 2
    assert result.deduped == 1


def test_filenames_are_sha256(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dest = tmp_path / "dest"
    _write(src / "a.webp", b"hello fuzz")

    seed_corpus(src, dest, format_filter="webp")
    files = list(dest.iterdir())
    assert len(files) == 1
    name = files[0].name
    # SHA-256 hex names are 64 lowercase hex chars (no extension).
    assert len(name) == 64
    assert all(c in "abcdef0123456789" for c in name)


def test_skips_outside_format_filter(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dest = tmp_path / "dest"
    _write(src / "image.webp", b"RIFF" + b"\x00" * 30)
    _write(src / "readme.md", b"# documentation, not a seed")
    _write(src / "notes.txt", b"some text")

    result = seed_corpus(src, dest, format_filter="webp")
    written = list(dest.iterdir())
    assert len(written) == 1
    assert result.skipped >= 2  # readme.md + notes.txt


def test_empty_source_dir_is_noop(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    dest = tmp_path / "dest"

    result = seed_corpus(src, dest, format_filter="webp")
    assert result.written == 0
    assert result.deduped == 0
    assert result.scanned == 0


def test_seeding_result_counts_total(tmp_path: Path) -> None:
    src = tmp_path / "src"
    dest = tmp_path / "dest"
    _write(src / "a.webp", b"AAA")
    _write(src / "b.webp", b"BBB")
    _write(src / "c.webp", b"AAA")  # dup of a
    _write(src / "ignore.md", b"docs")

    result = seed_corpus(src, dest, format_filter="webp")
    # scanned counts all files that matched format_filter; ignore.md is
    # under skipped (not scanned).
    assert result.scanned == 3
    assert result.written == 2
    assert result.deduped == 1
