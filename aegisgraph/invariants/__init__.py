"""AegisGraph Engine 3: InvariantCheck library.

The InvariantCheck engine encodes 25-30 SMA-specific security invariants
as CodeQL queries and Semgrep rules. Each invariant has:

  * A natural-language statement and rationale.
  * One or more engine encodings (codeql, semgrep, optional frida_dynamic).
  * Ground-truth fixtures (demo-vulnerable-app expected_violations counts).
  * A path-class mapping (which extraction path-classes the invariant
    applies to).
  * MASTG / SSDF mappings for compliance traceability.

A run against a target produces SARIF. The SARIF consolidator converts
each SARIF result into an `AG-IV-*` evidence record validating against
`schema/invariant-violation.schema.json`.

At M3.3 the library ships scaffolding + 5 invariants (INV-01, INV-07,
INV-09, INV-11, INV-13). The remaining 20-25 ship across M3-M11 per the
Phase II rollout plan.

Public API (importable from this package):

    aegisgraph.invariants.runner.sarif_consolidator.consolidate_sarif
    aegisgraph.invariants.runner.codeql_runner.run_codeql
    aegisgraph.invariants.runner.semgrep_runner.run_semgrep

The manifest is loaded with `aegisgraph.io.load_json`:

    from aegisgraph.io import load_json, repo_root
    manifest = load_json(repo_root() / "aegisgraph" / "invariants" / "manifest.json")
"""

from __future__ import annotations

from pathlib import Path


def manifest_path() -> Path:
    """Return the absolute path to the InvariantCheck manifest.json."""
    return Path(__file__).resolve().parent / "manifest.json"


def library_dir() -> Path:
    """Return the absolute path to the invariants library directory.

    The library/ tree holds the actual query files (codeql/*.ql,
    semgrep/*.yaml). Each manifest encoding `query` field is RELATIVE
    to manifest_path().parent — so e.g.
    `library/codeql/01_url_fetch_without_policy.ql` resolves to
    `manifest_path().parent / library / codeql / 01_url_fetch_without_policy.ql`.
    """
    return Path(__file__).resolve().parent / "library"


__all__ = ["manifest_path", "library_dir"]
