"""Corpus seeding for HarnessGen fuzz runs.

At M3.1 only `seed_from_smabench` ships — it consumes SMABench corpora
and writes a dedup'd seed corpus the libFuzzer harness can mount as its
initial corpus directory.

Future milestones will add:
  seed_from_polydiff   : PolyDiff URL-family witnesses as URL seeds
  dictionaries/        : format-aware libFuzzer dictionaries (.dict files)
"""

from __future__ import annotations
