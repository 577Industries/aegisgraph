"""Wave 9B (M9.2) — honest fuzz_status guard.

The self-hosted runner (T-M4.1) is not yet provisioned. Live Jazzer
runs of the Element X harness have therefore not happened. The
`validation_evidence.fuzz_status` field MUST report this honestly as
`not_run_runner_blocked`. The promoted status (`confirmed_reachable`)
rests purely on the structural-pattern match + harness-build evidence,
not on a fuzz crash.

When T-M4.1 lands and the runner emits actual crash bytes, a follow-up
record will flip this to `confirmed_crash` and reference an AG-CRASH-*
record. Until then this test fails loudly if anyone silently upgrades
the field — that would be an overclaim under the safety policy.
"""

from __future__ import annotations

from aegisgraph.crosssma.validation.elementx_linkpreview_xsma import (
    validated_record_path,
)
from aegisgraph.io import load_json


def _load_validated_record() -> dict:
    return load_json(validated_record_path())


def test_fuzz_status_is_not_run_runner_blocked() -> None:
    """T-M4.1 is BLOCKED. We do NOT pretend fuzz happened. The
    honest field is `not_run_runner_blocked` — if anyone changes
    this without provisioning a runner and attaching an AG-CRASH-*
    record, the change is an overclaim and this test fails."""
    record = _load_validated_record()
    fuzz_status = record["validation_evidence"]["fuzz_status"]
    assert fuzz_status == "not_run_runner_blocked", (
        f"validation_evidence.fuzz_status is {fuzz_status!r}; this "
        "field is gated by T-M4.1 (self-hosted runner). Until the "
        "runner is provisioned and emits a real AG-CRASH-* record, "
        "only `not_run_runner_blocked` is the honest value."
    )


def test_claim_state_is_validation_tasked_not_disclosed() -> None:
    """Promotion lifecycle: structural_only -> validation_tasked when
    we have build evidence but no live crash yet. We do NOT jump to
    reviewed / disclosed_* without the full evidence chain."""
    record = _load_validated_record()
    assert record["claim_state"] == "validation_tasked", (
        f"claim_state is {record['claim_state']!r}; with build-only "
        "evidence and no crash, validation_tasked is the only honest "
        "claim_state per plan §15 R-ENG-4."
    )


def test_validation_state_is_harness_validated() -> None:
    """validation_state mirrors the evidence level: harness_validated
    when we have a buildable harness but no dynamic crash. Dynamic
    validation is reserved for the post-runner state."""
    record = _load_validated_record()
    assert record["validation_state"] == "harness_validated", (
        f"validation_state is {record['validation_state']!r}; expected "
        "harness_validated since we have build evidence but no fuzz "
        "crash bytes."
    )
