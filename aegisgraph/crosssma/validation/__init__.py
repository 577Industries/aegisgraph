"""CrossSMA validation overlay records.

Wave 9B (M9.2) deliverable. When a HarnessGen build (or, later, a
fuzz run) lifts a candidate target cell out of `candidate_path` into
`confirmed_reachable`, the promotion is recorded as a *validation
overlay* AG-XSMA-VALIDATED-* record that:

  * carries `record_id` distinct from `candidate_id`;
  * pins `supersedes` at the prior candidate's `candidate_id`;
  * sets `hash_chain.previous_hash` to the prior candidate's
    `hash_chain.record_hash` so the lineage is forgery-evident;
  * narrows the focus cell (`target_id` + matching cell in
    `target_findings`) to `confirmed_reachable`, leaving other cells
    honest (still `candidate_path` / `dependency_absent`);
  * embeds a `validation_evidence` block (`kind`, `harness_path`,
    `harness_artifact_sha256`, `build_status`, `fuzz_status`,
    `build_evidence_ref`) so reviewers can re-run the artifact-present
    test and re-hash the harness file.

Constraints per task spec:

  * Re-use the existing Element X HarnessGen JVM artifact at
    `reprochain/harness/element_x_media/MediaRepositoryFuzzer.java`.
    Do NOT regenerate the harness from scratch.
  * Honest `fuzz_status: not_run_runner_blocked` — live Jazzer runs
    are T-M4.1 BLOCKED. The promotion rests on build evidence only.
  * Hash chain link verifies against the prior candidate produced by
    the deterministic Wave 3 matrix_renderer scaffold.

See `elementx_linkpreview_xsma.py` for the one validated cell that
this module ships today (AG-XSMA-VALIDATED-SIG-GP-001-ELX).
"""

from __future__ import annotations

from .elementx_linkpreview_xsma import (  # noqa: F401
    build_validation_record,
    emit_validation_record,
    validated_record_path,
)

__all__ = [
    "build_validation_record",
    "emit_validation_record",
    "validated_record_path",
]
