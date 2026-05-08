# AegisGraph Tier 3 Research

Private research workspace for 577 Industries' AegisGraph work under DARPA SBIR HR0011SB20254-12, Assessing Security of Encrypted Messaging Applications (ASEMA).

This repository is intentionally separate from `../../02_PUBLIC_RELEASE/ASEMA_Public_GitHub_Artifacts/`. The public v0.2 package remains untouched until a human-approved sanitized export is generated from this workspace.

## Research Posture

- Defensive, academic, and professional cybersecurity research only.
- No live-target probing, production account interaction, credentialed testing, or scanning without written authorization.
- No weaponized payloads, undisclosed crash inputs, raw target source redistribution, or private scanner dumps in exportable artifacts.
- Public artifacts are generated only through `make export-public-sanitized` and remain release candidates until explicitly approved.

## Workstreams

- ReproChain: isolated, private-by-default reproduction and reachability evidence for public-information parser failures.
- PolyDiff: differential parser fact-vector research for URL and OpenGraph parsing surfaces.
- Extraction: reproducible static extraction over pinned public SMA targets.
- SMABench: synthetic and public-source benchmark corpora with explicit authorization boundaries.
- Safety: validation, hash-chain provenance, and disclosure gates across every artifact.

## Quickstart

```bash
make tooling
make test
make extract
make reprochain-map
make polydiff-regression
make smabench
make validate
make reproduce
```

The CLI entrypoint is `aegisgraph` after installation, or `python3 -m aegisgraph.cli` from this checkout.

## Source of Truth

`SPEC.md` is copied from `../../00_CONTROL/specs/AegisGraph_Tier3_Spec.md` and remains the working technical specification. If implementation and spec diverge, update the spec deliberately.

The canonical specification for AegisGraph Tier 3 research is `SPEC.md`. All design intent, contracts, and deliverable definitions are in that document. Engineering decisions are recorded in `docs/decision-log/` (ADRs).

## Design Decisions

Architectural decisions are documented as ADRs in `docs/decision-log/`. Notable decisions include:

- **ADR 0007**: libwebp CVE-2023-4863 selected over FORCEDENTRY/iMessage as the ReproChain reachability target (BSD-3-Clause vendorable, well-documented, reachable from Signal+ElementX media decode)
- **ADR 0008**: URL-parser differential selected over MLS lifecycle as the PolyDiff focus (sourced regression corpus available, no protocol-cryptography depth required)
- **ADR 0009**: libwebp commit pins (vulnerable `7ba44f80...`, fix `902bc919...` from v1.3.2 / 2023-09-13)
- **ADR 0010**: schema additive-only policy (v1 records continue to validate after v2 schema migration)
- **ADR 0011**: public-export human gate (`release_authorized=False` until `AEGISGRAPH_RELEASE_AUTHORIZED=1` env AND `validator/sanitize_check.py` passes)
- **ADR 0020**: PolyDiff fact-vector v2 schema (45 axes; additive)
- **ADR 0021**: validator hardening (sanitize-check, traceability matrix, non-mutating mode)

See `docs/decision-log/README.md` for the complete index.

## Devcontainer

`make tooling-strict` requires the pinned devcontainer environment. The devcontainer pins Python 3.11.9, Clang 18 + libfuzzer-18, OpenJDK 21, CodeQL CLI 2.20.6, Semgrep 1.86.0, Go 1.22.5, Rust 1.79.0, Node 20, MobSF docker (digest-pinned), Android SDK 34 + NDK r26d. See `devcontainer/Dockerfile` and `devcontainer/post-create.sh`. Host environments without these tools will report `build_status='blocked_pending_toolchain'` honestly — see `reprochain/BUILD_STATUS.md` and `extraction/BUILD_STATUS.md`.

## Public Release Boundary

`make export-public-sanitized` produces a tarball at `exports/public-sanitized/`. The tarball is held with `release_authorized=False` until BOTH (a) `AEGISGRAPH_RELEASE_AUTHORIZED=1` is set AND (b) `validator/sanitize_check.py` passes. See ADR 0011 for the human gate rationale and `validator/sanitize_check.py` for the 12 substantive + 6 structural rules. The current public release at the v0.2 tag is in a separate repo (`577-Industries/asema-feasibility-artifacts`); the v0.3 release will land in the same repo on a `release/v0.3.0` branch after PI signs `RELEASE_APPROVAL.md`.

## Reproducing the Evidence

```bash
git clone https://github.com/577Industries/aegisgraph
cd aegisgraph && devcontainer up
make tooling-strict
make reproduce
python3 -m aegisgraph.cli validate
python3 -m validator.cli traceability
```
