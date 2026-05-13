"""AegisGraph Engine 4: CrossSMA.

When AegisGraph finds a structural pattern (parser disagreement,
invariant violation, harness crash, dependency vulnerability,
structural code pattern) in one Secure Messaging App (SMA), CrossSMA
checks whether the analogous pattern plausibly exists in other SMAs.

Module map:

  * `pattern_extractor` - finding -> canonical structural fingerprint
    (SHA-256 over JSON-canonicalized
    {pattern_type, family, axis, implementations_signature}).
  * `target_registry` - commit-pinned manifest of supported SMAs,
    sourced from `aegisgraph/crosssma/registry/targets.yaml`. Read-only
    in-process; ADR-style commit pins.
  * `queries/` - three v0 query primitives:
      - `shared_library_check.py`: "does target X depend on libL?"
      - `analogous_code_check.py`: "does target X have a function
        matching this structural pattern?"
      - `analogous_path_check.py`: "does target X have a graph path
        with this structure?"
  * `matrix_renderer` - produces finding x target matrix as AG-XSMA-*
    evidence records validating against
    schema/cross-target-candidate.schema.json.

Public API:

    from aegisgraph.crosssma.pattern_extractor import extract_pattern
    from aegisgraph.crosssma.target_registry import load_registry
    from aegisgraph.crosssma.matrix_renderer import (
        GraphThread, render_matrix, v03_graph_threads,
    )

See `Asemarefactor.md` Engine 4 + Phase II plan §6 / §15 R-ENG-4 for
the contract this module implements.
"""

from __future__ import annotations

from .pattern_extractor import PatternFingerprint, extract_pattern  # noqa: F401
from .target_registry import Target, load_registry  # noqa: F401
from .matrix_renderer import GraphThread, render_matrix, v03_graph_threads  # noqa: F401

__all__ = [
    "PatternFingerprint",
    "extract_pattern",
    "Target",
    "load_registry",
    "GraphThread",
    "render_matrix",
    "v03_graph_threads",
]
