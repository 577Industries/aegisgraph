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
