"""CrossSMA v0 query primitives.

Three query types fan out from a structural pattern to a target:

  * `shared_library_check` - dependency-graph match
    (does the target's dependency_snapshot include library L?)
  * `analogous_code_check` - path-class match against the pattern's
    family (coarse v0 heuristic; AST-aware match lands later)
  * `analogous_path_check` - graph-shape match against the target's
    extracted graph (loaded from `extraction/output/<target>/graph.json`
    when available, else returns unknown)

Each query returns a small dataclass result so the matrix renderer
can build cell statuses without re-running queries.
"""

from __future__ import annotations
