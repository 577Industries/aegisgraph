"""Ring 1: synthetic harness corpora.

Each subpackage contains a `generate.py` exposing a `generate(corpus_dir,
count=..., seed=...)` callable plus a CLI `__main__` entry point. All
output is deterministic given the seed and `corpus.metadata.json` carries
the full per-item SHA-256 manifest so byte-stability can be asserted at
the test level.
"""
