# 0002 Private ReproChain Handling

Decision: ReproChain outputs are private by default. Crash-inducing corpus files are never committed and public exports contain only hashes, structure notes, and bounded summaries unless manually approved.

Rationale: ASEMA research needs credible public-information reproduction while avoiding weaponization, target-app exploitation, or disclosure-sensitive payload publication.

Status: accepted.

## Related

- 0007 — libwebp over FORCEDENTRY (the specific target this private-handling policy applies to)
- 0009 — libwebp commit pins (vulnerable + fix SHAs are public; corpus is private)
- 0011 — public-export human gate (the export-approval mechanism)
- 0021 — validator hardening (the sanitize-check that enforces this policy on the export tree)

## Proposal claims

- C-NEW-RC — pre-disclosure simulation; private-by-default posture supports the limitation language.
- C-EVAL-2 — safety-scan / forbidden-categories posture for ReproChain outputs.

