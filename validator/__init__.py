"""validator package - hardened evidence verification for AegisGraph Tier 3.

Modules:
  - sanitize_check         Public-export forbidden-pattern + tool-output safety scan.
  - traceability_matrix    SPEC.md / proposal-claims / DSIP-requirements join → reports/.
  - validate_evidence      Backwards-compatible entrypoint (kept as a single-script);
                           ALSO exposes validate_repo_non_mutating() for the
                           --non-mutating mode that returns the report
                           without writing validation-report.json to disk.
  - cli                    Subcommand dispatcher (validate, strict-tooling,
                           sanitize-check, traceability).

The validator package is the *consumer* of aegisgraph internals; it must NOT
import private aegisgraph modules eagerly during package import (that would
make `aegisgraph.export` unable to lazily import `validator.sanitize_check`
without a circular import). Each submodule does its own heavy imports inside
function bodies where necessary.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
