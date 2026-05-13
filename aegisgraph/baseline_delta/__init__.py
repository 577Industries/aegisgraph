"""Baseline-tool delta report — Wave 9A (M14 deliverable).

Compares AegisGraph against three single-tool baselines (CodeQL alone,
Semgrep alone, MobSF alone) on the same pinned target source trees
(Signal Android @1043851 + Element X Android @91d265e6). The M14 metric
the report serves is "added by AegisGraph": findings present in AG
output AND absent in (codeql ∪ semgrep ∪ mobsf) at the same
(target, category, location_hash).

Public sub-API:

  * `aegisgraph.baseline_delta.runner` — per-tool subprocess orchestration.
    Each runner returns a structured envelope including a `status`
    field — `binary_missing` (CLI not on PATH), `apk_missing` (MobSF
    needs an APK that isn't available), `ran` (success), or `failed`.
    None of these raise; all are honest-output status codes.
  * `aegisgraph.baseline_delta.renderer` — finding normalization,
    overlap matrix, and "added by AegisGraph" delta column. The
    rendering layer is pure functional: takes a list of normalized
    findings, returns matrix structures. No I/O.

Design constraints (per Phase II plan §23 Agent 9A + §10 Rules 7/8/9):
  * No live target probing; we read from pre-existing extraction graphs
    and the anchored manifest. Source trees are NOT vendored here.
  * Sanitize-check Rule 8: SARIF source snippets are NOT propagated;
    location_hash is the canonical projection.
  * Sanitize-check Rule 9: crash-record completeness — not applicable
    here (we emit invariant_violation + finding records, not crashes).
  * MobSF APK absence emits MOBSF-LIMITED.md transparently; we never
    fabricate findings.

This package contains NO live-network code. All HTTP work that MobSF
needs is delegated to `extraction/mobsf/run_mobsf.py` which itself
already honors the offline policy.
"""

from __future__ import annotations

from . import renderer, runner

__all__ = ["renderer", "runner"]
