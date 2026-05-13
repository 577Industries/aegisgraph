"""AegisGraph reviewer workbench — strictly CLI-only.

Wave 8B (M8-M10) deliverable: a reviewer-facing command-line interface
that surfaces all AG-* records produced by the six discovery engines
(Extraction, PolyDiff, HarnessGen, InvariantCheck, CrossSMA, Disclosure)
and packages them into a reviewer-handoff artifact.

Strictly CLI-only — no web servers (Flask/FastAPI/aiohttp) and no TUIs
(curses/textual/rich.live/prompt_toolkit). Enforced by negative tests in
tests/workbench/test_no_web_imports.py and test_no_tui_imports.py.

Per ADR-0010 (additive schema only): `promote` writes a NEW record with
`supersedes: <prior_id>` and a new `claim_state`; it never edits a prior
record. The hash chain links new -> prior via
`hash_chain.previous_hash` = prior's `hash_chain.record_hash`.

Modules:
  - registry         : on-disk scan for AG-* records across engine outputs
  - filters          : FindingFilters + FilterSpec parsing (engine, target,
                        claim_state)
  - finding_list     : list_findings(root, filters) -> list[FindingRow]
  - finding_detail   : show_finding(root, record_id) -> dict (resolves
                        evidence_refs + walks supersedes chain)
  - packet_export    : export_packet(root, top_n, out_dir, filter_spec)
                        -> manifest dict; emits exports/reviewer-packet/
                        <ISO_DATE>/ tree with manifest.json, bundle.md,
                        findings/<record_id>.json + .evidence.md,
                        and checksums.sha256.
  - cli              : subparser mounted from aegisgraph.cli.build_parser
"""

__all__ = [
    "filters",
    "finding_detail",
    "finding_list",
    "packet_export",
    "registry",
]
