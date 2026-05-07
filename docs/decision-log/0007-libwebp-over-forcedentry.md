# 0007 libwebp (CVE-2023-4863) over FORCEDENTRY (CVE-2021-30860)

Status: accepted (placeholder; reprochain stream will refine).

## Decision

Select libwebp CVE-2023-4863 as the initial ReproChain research target,
NOT the FORCEDENTRY / iMessage CVE-2021-30860 path.

## Rationale

| Axis | libwebp CVE-2023-4863 | FORCEDENTRY CVE-2021-30860 |
|---|---|---|
| License | BSD-3-Clause; vendorable into `reprochain/vendor/libwebp/` for an ASAN+libFuzzer harness | Apple-proprietary; cannot vendor or run a deterministic harness |
| Documentation | upstream commit log + Google Project Zero writeup + multiple public root-cause posts | Citizen Lab and Google P0 disclosures only; no upstream commit history |
| Reachability | Inbound media decode path is reachable in every SMA we benchmark (Signal, Element-X, libSignal-derived clients, Matrix clients) | Reachable only via Apple iMessage / CoreGraphics; out of scope for cross-platform SMA evaluation |
| Determinism | Single-file fuzz harness (`webp_fuzzer.c` upstream) reproduces the heap overflow in seconds on Clang 18 + libFuzzer | Closed-source CoreGraphics path; reproduction would require Apple internals |
| Defensive narrative | Lets us demonstrate the same parser-fragility class without privileging Apple's stack as the canonical example | Restricts the narrative to one vendor's iMessage workflow |

## Constraints carried into the harness

- Only the harness-relevant subset of upstream libwebp sources lives in
  `reprochain/vendor/libwebp/` (vendored-library, NOT target source). The
  reprochain-proof stream owns the exact subset.
- Vulnerable + fixed commit SHAs are pinned in the follower ADR
  (`0009-libwebp-cve-2023-4863-pins.md`). They are NOT pinned here.
- Harness inputs are corpus seeds drawn from upstream libwebp's own
  fuzzing seed corpus (already public). No undisclosed crash inputs are
  ever committed; safety scanner enforces this via the
  `undisclosed_crash_payload` rule in `aegisgraph/safety.py`.

## Out of scope

- This ADR does not assert that libwebp ships in Signal, Element-X, or
  any other SMA. Reachability claims belong in evidence records produced
  by the extraction stream, with their own
  validation_task and limitations.
- ReproChain produces evidence about the libwebp parser. It does NOT
  produce evidence about any specific SMA being vulnerable today.

## What flips this decision

The integration stream re-opens this ADR if any of the following happen:

1. libwebp upstream changes its license (effectively impossible given
   prior commits, but stated for completeness).
2. The reprochain-proof stream demonstrates that the upstream fuzz
   harness no longer reaches the historical bug after a Clang 18 +
   libFuzzer rebuild — at which point we either pick a different
   versioned vulnerability in the same parser or reconsider the target.
3. A non-Apple FORCEDENTRY-class media bug appears in a vendorable,
   public-source codec with a deterministic harness. (Would augment, not
   replace.)
