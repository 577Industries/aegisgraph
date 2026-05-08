# 0003 libwebp Selection

Decision: keep CVE-2023-4863/libwebp as the initial ReproChain research target, pending exact vulnerable and fixed commit confirmation.

Rationale: libwebp is a public, broadly deployed parser surface that supports the ASEMA narrative around inbound media parsing, remote reachability, and native decoder boundaries without requiring live SMA targeting.

Status: accepted with commit-pin gate.

## Related

- 0007 — libwebp over FORCEDENTRY (refines this Phase-0 selection with a candidate-set rationale matrix)
- 0009 — libwebp CVE-2023-4863 commit pins (closes the commit-pin gate from this ADR)

## Proposal claims

- C-NEW-RC — selection of the ReproChain reachability target.
- C-ABS-5 — pre-disclosure simulation depends on this target choice.

