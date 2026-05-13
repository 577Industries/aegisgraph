# Figure pack F15-F22 (v0.4 engines + schema overlay) — Wave 7B coordination memo

**Date:** 2026-05-13
**Branch:** `stream/shared-public`
**Wave:** 7B (figure pack render)
**Plan reference:** `/home/twawe/.claude/plans/so-i-have-a-structured-milner.md` §21 Agent 7B

## Scope

This memo records Wave 7B — rendering of 8 new figures (F15-F22)
covering the v0.4 engine pack and the schema v1 -> v2 additive
overlay. Engineering code is **not** touched by this pass. All edits
land in `03_PROPOSAL/active-package/02_figures_and_storyboard/` at the
workspace level; only this coordination memo is committed on
`stream/shared-public`.

Render path is matplotlib fallback only — `mmdc` (`@mermaid-js/mermaid-cli`)
remains absent on the build host (per
`02_figures_and_storyboard/FIGURES_BUILD_STATUS.md` v0.3 status table:
"NOT INSTALLED — `npx -y @mermaid-js/mermaid-cli@latest` failed with
`EROFS: read-only file system`"). The canonical `.mmd` sources are
saved at `sources/F{15..22}*.mmd` for future devcontainer mermaid
re-render with `npx -y @mermaid-js/mermaid-cli@latest` once the npm
cache is writable.

## Workspace-level edits applied (NOT in this git repo)

All five workspace-level files are under
`/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package/02_figures_and_storyboard/`:

1. **`scripts/render_figures.py`** — added 8 new render functions
   (`render_f15_engine_architecture`, ..., `render_f22_schema_v2_overlay`),
   added `RENDERERS_V04` list, added `--v04` argparse flag, extended
   `--only` filter to consult all known renderers. Existing F1-F14
   render functions are untouched. Added `import math` for the radial
   layout in F15 / F16. The established `COLORS` palette is reused
   unchanged.

2. **`Makefile`** — added `figures-v04` target rendering F15-F22.
   `figures-all` now renders F1-F22 (was F1-F14). Help text updated.
   The `MPLCONFIGDIR` pattern is preserved.

3. **`sources/F{15..22}-<slug>.mmd`** — 8 new canonical mermaid
   sources. These document the canonical mermaid intent for future
   devcontainer re-render; the shipping artifacts today are the
   matplotlib PNGs.

4. **`figures-and-demo-storyboard.md`** — 8 new figure sections
   (F15-F22) inserted between Figure 7 and the Month-by-Month
   Demo Storyboard table. Each section is ~10-20 lines and points to
   the corresponding `.mmd` source.

5. **`FIGURES_BUILD_STATUS.md`** — appended a "v0.4.1 — F15-F22 added"
   block with the full status table (render method, dimensions, bytes,
   SHA-256 prefix, timestamp) for each of F15-F22, plus a build-command
   reference and a Wave 7A embedding note.

## Rendered PNGs

All 8 PNGs live at
`03_PROPOSAL/active-package/02_figures_and_storyboard/rendered/`:

| ID  | Slug                     | Bytes   | Width x Height |
|-----|--------------------------|---------|----------------|
| F15 | engine-architecture      | 150,482 | 1635x1260      |
| F16 | discovery-loop           | 109,908 | 1635x1260      |
| F17 | polydiff-multi-family    | 190,625 | 1830x1260      |
| F18 | harnessgen-flow          | 136,230 | 2010x1260      |
| F19 | invariantcheck-card      | 244,583 | 2010x1197      |
| F20 | crosssma-matrix          | 156,884 | 1994x1252      |
| F21 | disclosure-state-diagram | 146,560 | 1839x1260      |
| F22 | schema-v2-overlay        | 267,255 | 2235x2160      |

Every PNG is well under the 1 MB ceiling specified in the plan; the
largest is F22 at 267 KB (the schema v1/v2 side-by-side panel needs
extra vertical space for the 35-row dual list). All PNGs were rendered
with `dpi=150` at figsizes between 11x8.5 and 15x14.5 inches, matching
the F1-F14 style conventions.

## Data sources consulted

- **F19** (InvariantCheck Library Card) — sampled the INV-01 manifest
  entry from
  `aegisgraph/invariants/manifest.json` (statement, rationale,
  encodings list, ground_truth, applicable_path_classes, MASTG / SSDF
  mappings). All shown text is verbatim or hand-trimmed to fit the
  card; no extra claims are introduced. Across the v0.4.1 cut the
  library carries 15 invariants (12 production: 10 CodeQL + 2
  Semgrep); INV-01 is shown as a sample only.

- **F20** (CrossSMA matrix) — used the 4 target ids from
  `aegisgraph/crosssma/registry/targets.yaml`
  (`signal-android`, `element-x-android`, `wire-android`,
  `telegram-android`) and the 6 v0.3 graph-thread ids
  (`SIG-GP-001..003`, `ELX-GP-001..003`) from
  `04_evidence/v0.3/aegisgraph-v0.3-evidence.json`. The status
  assignment is illustrative and honest:
  - Own-target diagonal cells: `confirmed_reachable`.
  - Sibling-family cells: `candidate_path` (or `parser_differs` for
    SIG-GP-003 / ELX-GP-003 which depend on Signal- and Matrix-specific
    parsers).
  - Wire cells: mix of `candidate_path` and `dependency_absent` based
    on the `libwebp` / `okhttp` overlap declared in `dependency_snapshot`.
  - Telegram cells: uniformly `unknown` (`commit: TODO-TELEGRAM-COMMIT`;
    M11 graduation).

- **F21** (Coordinated-Disclosure state diagram) — modeled on the
  transition rules in `aegisgraph/claims.py` and the
  `claim_state` / `disclosure_status` enums in
  `schema/evidence.schema.json`. The 5 state boxes are Anchored,
  Reviewed, Reviewed-Embargoed, Disclosed-Public, Retired. The
  `Reviewed -> Reviewed-Embargoed` edge is drawn red and annotated
  "counsel review required" to make the counsel gate visible.

- **F22** (Schema v1 -> v2 overlay) — node + edge enum lists drawn
  from `schema/evidence.schema.json` (`node_type` enum: 10 v1 + 6 v2
  new types; relationship strings: 11 v1 conventional + 6 v2 new
  semantic relationships per ADR-0001 additive extension). Same
  `discovery_engine` and `finding_type` enums confirmed the v2
  additions.

- **F17** (PolyDiff multi-family lattice) — sampled 6 fact axes per
  family from `schema/fact-vector-{image,opengraph,deeplink,qr,proto}.schema.json`.
  The `url` family has no separate schema file at the v0.4.1 cut, so its
  axes (`scheme`, `host`, `userinfo`, `port`, `path`, `query`) are
  drawn from the canonical RFC 3986 URI components matching what
  PolyDiff Extended currently produces; this mirrors the existing F13
  PolyDiff schematic.

## Build reproducibility

```bash
cd 03_PROPOSAL/active-package/02_figures_and_storyboard
make figures-v04        # renders F15-F22 only
# or
make figures-all        # renders F1-F22 (Wave 7B + v0.3 pack)
ls rendered/F1[5-9]*.png rendered/F2[0-2]*.png | wc -l   # expect 8
```

`make figures-v04` exit code: **0** on this pass.

## Constraints honored

- **No engineering code edits.** Only workspace-level files under
  `02_figures_and_storyboard/` are touched.
- **No overlap with other Wave 7 agents.** Master proposal markdown,
  submission binder, and CETM are untouched.
- **mmdc fallback policy preserved.** Per FIGURES_BUILD_STATUS.md, all
  v0.3 figures (F1-F14) shipped via matplotlib fallback; F15-F22
  follow the same convention and include `.mmd` canonical sources for
  future devcontainer re-render.
- **Each PNG <= 1 MB.** Largest is F22 at 267 KB.
- **Style match with F1-F14.** Same `COLORS` dict, same `FancyBboxPatch`
  + `FancyArrowPatch` idioms, same `dpi=150` + `bbox_inches="tight"`
  save pattern.

## Wave 7A coupling

The Wave 7A proposal-narrative pass (PROPOSAL_V041_FINALIZATION_PASS.md,
commit `2026-05-13`) embeds F15-F22 figure references in:

- §5.3 Evidence Graph Schema -> F22 (schema v2 overlay)
- §6.8 PolyDiff Extended -> F15 + F17
- §6.9 HarnessGen -> F18
- §6.10 InvariantCheck -> F19
- §6.11 CrossSMA -> F20
- §6.12 Coordinated Disclosure -> F21
- §5.x discovery-loop preamble -> F16

Wave 7B does not modify the master proposal; the figure references
ship inert today and will resolve to the rendered PNGs the moment the
v0.4.1 PDF re-render kicks off (Wave 7E / verification pass).

## Verification grep commands

From the workspace root:

```bash
PROP="/home/twawe/577i-Projects/SBIR Working Folder/ASEMA/03_PROPOSAL/active-package"
FIG="$PROP/02_figures_and_storyboard"

# 8 new rendered PNGs:
ls "$FIG/rendered/" | grep -E '^F(1[5-9]|2[0-2])-' | wc -l   # 8

# 8 new .mmd sources:
ls "$FIG/sources/" | grep -E '^F(1[5-9]|2[0-2])-' | wc -l   # 8

# Make target works:
cd "$FIG" && make figures-v04 >/dev/null && echo OK

# Storyboard mentions all 8:
for n in 15 16 17 18 19 20 21 22; do
  grep -q "^## Figure $n:" "$FIG/figures-and-demo-storyboard.md" \
    && echo "F$n: OK"
done

# Status block exists:
grep -q "v0.4.1 — F15-F22 added" "$FIG/FIGURES_BUILD_STATUS.md" && echo OK
```

## Open questions / followups

- **Devcontainer re-render.** When mmdc becomes available (devcontainer
  pass), re-rendering F15-F22 from `sources/*.mmd` should yield visually
  consistent output. The two figures that are not natural for mermaid
  (F19 card view, F20 coloured matrix) intentionally keep the
  matplotlib fallback as the canonical artifact; their `.mmd` files
  document the row/column/field intent only.
- **PDF embed.** The master-proposal PDF re-render that consumes the
  v0.4.1 figure references is Wave 7E / verification scope; this pass
  only commits the PNGs to the workspace.

## Commit

A single commit on `stream/shared-public`:

```
docs(figures): F15-F22 figure pack rendered (Wave 7B)

Eight new figures rendered via matplotlib fallback (mmdc still
unavailable per FIGURES_BUILD_STATUS.md). Canonical .mmd sources
saved at sources/F{15..22}.mmd. Makefile target figures-v04 added.
figures-and-demo-storyboard.md extended with 8 new sections.
```

No push.
