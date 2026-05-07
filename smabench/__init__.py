"""SMABench - Tier 3 synthetic / public-source / authorized-dynamic harness suite.

This package contains the generators (Ring 1) and consumers (Ring 2) that
sit beneath the orchestrator at `aegisgraph.smabench`. Ring 3 is an
authorization-only placeholder; nothing under this package performs live
target probing, credentialed interaction, or weaponized payload generation.

The corpora produced here are deterministic (seeded RNG, sorted output,
canonical JSON metadata) so a third-party can byte-compare two runs of
the same generator and confirm reproducibility.
"""
