# AegisGraph DP2 Feasibility Hardening: Tier-3 Technical Specification

**Project:** 577 Industries — AegisGraph for DARPA SBIR HR0011SB20254-12 (ASEMA)
**Document type:** Engineering specification, to be executed iteratively with Claude Code over an indefinite timeline
**Goal:** Move AegisGraph's Phase-I-equivalent feasibility from "thoughtful methodology paper" to "DP2 proposal whose technical core is hard to ignore."
**Scope:** This document covers four workstreams (ReproChain, PolyDiff, Extraction, SMABench), the evidence schema that ties them together, and a phased execution plan. It is a working spec — every section is intended to be edited as the work progresses.

---

## 0. How to Use This Document

This is the master technical specification. Hand it (or relevant sections of it) to Claude Code as the source of truth. Each workstream is broken into self-contained phases that can be executed mostly independently. Where a phase depends on output from another phase, that dependency is called out explicitly.

Conventions used throughout:

- **Decision points** are flagged `[DECIDE]` with the call the human needs to make.
- **Open questions** are flagged `[OPEN]`.
- **Out-of-scope items** are flagged `[OOS]` so we don't accidentally drift into them.
- File and directory paths use the proposed repo layout in §3.

If the spec and the code disagree, the code wins and the spec gets updated. Treat this as a living document, not a contract.

---

## 1. Strategic Context

### 1.1 What we are trying to prove

ASEMA reviewers will judge this DP2 against three implicit questions:

1. **Has this team done credible vulnerability research, not just methodology?**
2. **Does the prototype actually work on real targets, or only on schemas?**
3. **Is there a novel capability here that other teams aren't already shipping?**

The current AegisGraph v0.3 evidence release is strong on documentation discipline and weak on all three of those questions. This spec is designed to close those gaps with two concrete technical contributions:

- **ReproChain** — a public-information reproduction of CVE-2023-4863 (libwebp `BuildHuffmanTable` heap overflow), including a static reachability graph in Signal Android and Element X Android showing that AegisGraph would have surfaced the relevant attack-surface evidence ahead of the September 2023 disclosure.
- **PolyDiff** — an automated differential-parser fuzzing capability targeting URL/URI/IRI parsers and OpenGraph metadata extractors reachable from SMA link-preview pipelines, with a triage layer that flags security-relevant disagreements.

Two supporting workstreams make those contributions stand up:

- **Workstream C (Extraction)** replaces the v0.3 handwritten graph threads with automated extraction over Signal Android and Element X Android, including real CodeQL queries, a real Semgrep ruleset, and a working MobSF integration.
- **Workstream D (SMABench)** turns the three-ring synthetic / public-source / authorized-dynamic harness scaffolding into actual runnable harnesses with corpora and CI.

### 1.2 What we are explicitly not doing

- We are not pursuing publications, conference talks, or external validator engagement letters as part of this spec. Those are out of scope per the project owner.
- We are not attempting a ForcedEntry / JBIG2 reproduction. iOS-only chain, requires CoreGraphics expertise we don't have time to build, and the existing v0.3 corpus is Android.
- We are not weaponizing CVE-2023-4863. The reproduction stops at AddressSanitizer-confirmed heap corruption on a vendored vulnerable libwebp commit. No code execution, no sandbox escape, no production app targeting.
- We are not running PolyDiff against live SMA services, accounts, or production deployments. All differential fuzzing happens against parser libraries in isolated harnesses.
- We are not making security claims about Signal or Element/Matrix on the basis of static analysis alone. Anything we surface gets the AegisGraph claim-state treatment: observed → anchored → scored → tasked → reviewed → limited/accepted.

### 1.3 What "done" looks like

The work is done when, at minimum:

1. `aegisgraph reprochain run` produces a reproducible AddressSanitizer trace of CVE-2023-4863 against a vendored vulnerable libwebp, plus a clean run against the patched commit.
2. `aegisgraph reprochain map` produces a JSON evidence record showing the call graph from Signal Android's `MmsAttachment` ingest down through Glide / native decode to a libwebp call site, and the equivalent for Element X Android via Coil. The record carries the AegisGraph score vector and is anchored to commit-pinned source URLs.
3. `aegisgraph polydiff run --target url-parsers` produces (a) a corpus of disagreement cases, (b) a triaged shortlist of security-relevant disagreements with a reproducible Python repro for each, and (c) a regression suite that catches at least three known historical URL-parser disagreement bugs (e.g., one of the documented `okhttp HttpUrl` vs. `java.net.URI` cases) without seeding.
4. The full pipeline is reproducible from a clean checkout via `make reproduce` in under one hour on a 16-core developer machine.
5. The evidence schema in §8 validates against everything ReproChain and PolyDiff produce, and the validator script catches deliberate corruption tests.

A "stretch done" — beyond the minimum — is in §1.4.

### 1.4 Stretch goals (only if everything above is real)

- A second reproduction: CVE-2019-11932 (WhatsApp `libpl_droidsonroids_gif` double-free). Adds a second CVE to the ReproChain corpus, demonstrates that the methodology generalizes.
- PolyDiff extended to OpenGraph metadata extractors (jsoup vs. lxml vs. Gumbo vs. fast-html-parser).
- A novel-finding pipeline: any disagreement that's never appeared in public CVE corpora, with a triage decision tree for whether it warrants disclosure.
- A defense-side companion to ReproChain: a CodeQL query pack that flags the structural pattern of CVE-2023-4863 (variable-length attacker-controlled allocation feeding a fixed-size structure used by a hot loop) across a corpus of mobile codebases.

Stretch goals are explicitly *not required* for the spec to be successful. They go in the backlog.

---

## 2. The Two Headline Deliverables (decisions and rationale)

### 2.1 Why CVE-2023-4863 specifically

The candidate set:

| Candidate | Pros | Cons | Verdict |
|---|---|---|---|
| ForcedEntry (CVE-2021-30860, JBIG2) | Most famous; deeply documented Project Zero writeup | iOS-only; requires CoreGraphics/CoreText expertise; not Android; existing v0.3 corpus is Android | Reject |
| BLASTPASS (CVE-2023-41064 + 41061) | Recent, headline-grabbing | Sparse public details; requires PassKit/ImageIO internals | Reject |
| WhatsApp VOIP RCE (CVE-2019-3568) | Widely cited; cross-platform | WhatsApp source not public; RTCP exploitation specifics scattered | Reject |
| WhatsApp GIF double-free (CVE-2019-11932) | Public PoC; Android; well-documented Awakened writeup | Library `libpl_droidsonroids_gif` is small and not used by Signal/Element | Stretch |
| **libwebp (CVE-2023-4863)** | BSD-licensed open library; affected basically every SMA; well-documented bug; reachable from Signal Android and Element X Android via image-load paths; clean reproduction stops at memory corruption | Library is small enough that a static analyzer "finding" it could be argued as cherry-picked | **Selected** |
| Matrix/Megolm Albrecht et al. attacks (2022) | High-impact academic work; multi-CVE | Requires protocol-cryptography depth; harder to "reproduce" without authoring an attacker-Matrix client | Reject (consider as future work) |

The libwebp choice is load-bearing for the ReproChain narrative. The story it lets us tell to ASEMA reviewers:

> In September 2023, a single bug in a parser used by every major secure messenger turned a phone number plus a crafted image into universal heap corruption. AegisGraph's attack-surface modeling explicitly weights remote reachability, parser complexity, and native/FFI boundaries — exactly the dimensions where this bug lived. We reproduced the crash from public information against a vendored vulnerable libwebp, traced the call path from inbound media in both Signal Android and Element X Android, and recorded the resulting graph paths in our evidence model. The score vector for those paths is in the high-priority band. Had AegisGraph existed pre-disclosure and been pointed at either codebase's media pipeline, this exact subgraph would have been in the top-five attack-surface evidence records — not as a defect claim, but as a "validate this parser path under a fuzzer" task.

That's a story. The current v0.3 is not.

### 2.2 Why differential URL/OpenGraph parser fuzzing as the novel capability

The candidate set the user proposed:

| Candidate | Demonstrability without crypto expertise | Likelihood of real findings | Composes with libwebp story | Automation feasibility | Verdict |
|---|---|---|---|---|---|
| Parser-disagreement bugs (URL, OpenGraph, image format detection, markdown) | High | High | Yes — both are parser problems | High | **Selected** |
| Group-state rollback windows (Megolm/MLS) | Low | Medium | Weak | Medium | Reject |
| MLS/Olm session lifecycle reachability | Medium | Medium-low | Weak | Medium | Reject |

Differential parser fuzzing is the right call because:

1. **Real research lineage.** McKeeman's "Differential Testing for Software" (1998), DeMott et al., the ALPACA / certificate-confusion line of work, langsec, Orange Tsai's "A New Era of SSRF" (2017), Snyk's URL-parser study (2022). We are not inventing the technique; we are pointing it at the right surface and wiring it into AegisGraph's evidence model.
2. **Real published bugs to validate against.** CVE-2017-15086 (jsoup), CVE-2020-7793 (jsoup `HttpsConverter`), the various Node `url` vs WHATWG-URL disagreements, the okhttp `HttpUrl` userinfo cases, Bishop Fox's `urllib3` work. We can build a regression set out of public bugs and demonstrate that PolyDiff finds them without seeding.
3. **Real attack surface in SMAs.** Every SMA has a link-preview pipeline. Every link-preview pipeline parses URLs at least three times — once to validate user input, once to fetch metadata, once to render. Those three parses are often three different libraries. Disagreement → confusion → security impact (SSRF, origin spoofing, redirect-to-localhost, IDN attacks).
4. **Composes with libwebp.** Both the reproduction and the novel capability are about parsers reachable from inbound messages. The unified narrative is *"SMAs are attack-surface-hostile because they parse a lot of attacker-controlled bytes; we model that surface, we reproduce a public bug that exploited it, and we automate the discovery of the next one."*

### 2.3 What success means for each

For ReproChain, success is a binary: does `aegisgraph reprochain run` produce ASAN heap-buffer-overflow on the vulnerable commit and clean output on the patched commit, every time, on any reviewer's laptop? Plus the evidence record in §8 schema validates.

For PolyDiff, success has three tiers:

- **Tier-P1:** PolyDiff rediscovers ≥3 known historical URL-parser disagreements without seeding (regression set defined in §5.7).
- **Tier-P2:** PolyDiff finds ≥1 disagreement that is not in the regression set, that survives triage as "potentially security-relevant," with a written analysis of impact.
- **Tier-P3:** PolyDiff finds a novel disagreement that we can responsibly disclose. (Not required; documented if it happens.)

---

## 3. Repository Architecture & Tooling

### 3.1 Top-level layout

```
aegisgraph/
├── README.md                     # high-level orientation
├── SPEC.md                       # this document, kept in sync
├── Makefile                      # `make reproduce`, `make test`, `make extract`, `make polydiff`
├── flake.nix or devcontainer/    # reproducible dev environment (see §3.4)
├── .github/workflows/            # CI pipelines
├── extraction/                   # Workstream C: automated graph extraction
│   ├── codeql/                   # CodeQL query packs (per target)
│   ├── semgrep/                  # Semgrep ruleset
│   ├── mobsf/                    # MobSF runner + result normalizer
│   ├── manifest/                 # AndroidManifest analyzers
│   ├── adapters/                 # raw output → AegisGraph evidence
│   └── targets/
│       ├── signal-android/       # pinned commit, build script, extraction config
│       └── element-x-android/    # pinned commit, build script, extraction config
├── reprochain/                   # Workstream A: CVE-2023-4863 reproduction
│   ├── vendor/libwebp/           # pinned vulnerable + patched commits as submodules
│   ├── harness/                  # libfuzzer + ASAN harness
│   ├── corpora/                  # crash-triggering inputs (vetted)
│   ├── mapping/                  # static reachability evidence in target apps
│   └── evidence/                 # AegisGraph-format records
├── polydiff/                     # Workstream B: differential parser fuzzing
│   ├── parsers/                  # wrappers per parser implementation
│   │   ├── java_net_uri/
│   │   ├── android_net_uri/
│   │   ├── okhttp_httpurl/
│   │   ├── rust_url/
│   │   ├── python_urllib/
│   │   ├── go_neturl/
│   │   └── libcurl/
│   ├── factvec/                  # fact-vector schema and normalization
│   ├── disagreement/             # detector + clusterer
│   ├── triage/                   # security-relevance classifier
│   ├── fuzzer/                   # libfuzzer driver + corpus
│   ├── regression/               # known-disagreement regression set
│   └── evidence/                 # AegisGraph-format records
├── smabench/                     # Workstream D: synthetic / public-source harnesses
│   ├── ring1/                    # synthetic fixtures (URL, QR, deep-link, sync, PQ)
│   ├── ring2/                    # public-source extraction tasks
│   └── ring3/                    # placeholder; future authorized work
├── schema/                       # JSON Schemas for evidence, scores, claims, recs
├── validator/                    # validate-evidence.{mjs,py} — schema + safety scan
├── reports/                      # generated DARPA-facing artifacts
└── docs/                         # internal docs, decision log, ADRs
```

### 3.2 Languages, runtimes, build systems

- **Extraction**: Python 3.11+ for adapters and orchestration; CodeQL for queries; Semgrep CLI; MobSF in Docker.
- **ReproChain**: C/C++ for libwebp itself; Clang with `-fsanitize=address,fuzzer`; Python 3.11 for the orchestration and evidence-mapping layer.
- **PolyDiff**: A polyglot test harness. Each parser wrapper runs in its native runtime (Java in JVM, Rust in cargo, Python natively, Go natively, libcurl through ctypes). The orchestrator and disagreement detector are Python. Fuzz drivers are libfuzzer (C/Rust) and AFL++ where appropriate; Atheris is a fallback for Python-side fuzzing.
- **Schema/validator**: JSON Schema 2020-12. Validator in both Node (existing v0.3 baseline) and Python (canonical from this spec forward).

`[DECIDE]` Whether to keep the Node validator alongside Python or migrate to Python-only. Default: keep Node for v0.3 backwards compatibility, treat Python as canonical going forward.

### 3.3 Tooling baseline (the "CodeQL not on PATH" embarrassment, fixed)

The v0.3 SOTA matrix said CodeQL and MobSF were "Not run, unavailable on PATH on 2026-05-04." That is a credibility-killer in front of DARPA reviewers. Workstream C resolves it by making the tooling part of the repo, not the user's workstation:

- A `Dockerfile` (or Nix flake) that pins:
  - CodeQL CLI 2.20.x with the `codeql/java-queries` and `codeql/python-queries` packs
  - MobSF 4.x in its own container
  - Semgrep latest stable
  - Clang 18+ with libfuzzer support
  - JDK 21, Android SDK build-tools required to build a Signal Android codeql DB
  - All the parser-language toolchains (rustc, go, python3.11, openjdk, node)
- A `make tooling` target that verifies all the above are available and emits versions to `tooling-versions.txt`. The validator script refuses to emit a SOTA matrix unless `tooling-versions.txt` is present and current.
- Every entry in the SOTA matrix records (a) tool version, (b) command line, (c) input slice, (d) raw output hash, (e) normalized output. No more "Not run, unavailable on PATH."

### 3.4 Reproducibility contract

Every artifact in the evidence package must be regenerable with one command (`make reproduce`) from a clean clone, given the dev container. CI runs `make reproduce` weekly on the pinned commits and posts checksum diffs. Drift is flagged.

This is the single biggest defense against the "your DP2 evidence is hand-curated" critique.

---

## 4. Workstream A — ReproChain (CVE-2023-4863)

### 4.1 Background you'll want to load before working on this

CVE-2023-4863 is a heap buffer overflow in libwebp's `BuildHuffmanTable` function (`huffman_utils.c`), reachable through the lossless WebP (VP8L) decoding path. It was discovered jointly by Apple SEAR and Citizen Lab and disclosed September 2023. The fix shipped in libwebp 1.3.2.

The bug class: a Huffman-table builder that allocates output table memory based on one computation but then writes to it under a different (attacker-controlled) computation. When the attacker-controlled inputs cause more entries to be written than the allocation accounts for, you get a heap overflow. In the libwebp case, the variable-length code lengths supplied in the WebP image's color cache section can cause the construction loop to write past the allocated `HuffmanCode` table.

Public references to load:
- libwebp upstream commit landing the fix (the public Chromium issue tracker tracks it; pin the exact upstream hash in the vendored submodule).
- Ben Hawkes / @benhawkes blog post from late September 2023 analyzing the bug pattern.
- The Chromium security advisory.
- The Project Zero bug tracker entry once it became public.
- libwebp `huffman_utils.c` and `huffman_utils.h` in the vulnerable commit.

`[OPEN]` We need to confirm the exact pre-fix commit hash and exact post-fix commit hash for libwebp. Phase A1 task.

### 4.2 Phase A1 — Vendor the library and stand up a harness

Goal: get a reproducible build of libwebp at both the vulnerable and patched commits, runnable from `make`.

Tasks:

1. Add libwebp as a git submodule under `reprochain/vendor/libwebp/`. Pin two refs: `libwebp-vuln` (pre-fix) and `libwebp-fix` (post-fix). Use the upstream `chromium/libwebp` repo, not a fork.
2. Write `reprochain/build.sh` that builds libwebp twice (vuln, fix) with `-O1 -g -fsanitize=address,fuzzer-no-link` and produces two static archives (`libwebp-vuln.a`, `libwebp-fix.a`).
3. Write `reprochain/harness/fuzz_webp_decode.cc`, a libFuzzer harness that:
   - Receives `(data, size)` from libfuzzer.
   - Calls `WebPDecode(data, size, ...)` (or the lower-level `WebPDecodeRGBA`/`VP8LDecodeImage` depending on what the bug requires).
   - Returns 0 on no crash, non-zero on confirmed crash.
4. Build two harness binaries: `fuzz_webp_decode_vuln` and `fuzz_webp_decode_fix`. Both link against ASAN.
5. `make reprochain-harness` builds both. CI verifies they exist and are ASAN-instrumented.

Acceptance: `./fuzz_webp_decode_vuln -help=1` runs and prints libfuzzer help text. ASAN is detected in `nm` output.

### 4.3 Phase A2 — Reproduce the crash

Goal: confirm the harness crashes the vulnerable build and not the patched build, on a publicly-derived input.

Tasks:

1. Construct a crash-triggering WebP file from public information. Two approaches in parallel:
   - **Crafted-from-spec.** Read the Hawkes writeup and the libwebp source at the vulnerable commit. Hand-construct a minimal WebP with a VP8L chunk whose color-cache Huffman code lengths trigger the overflow. Document the construction in `reprochain/corpora/handcrafted/README.md` so a reviewer can rebuild it.
   - **Fuzzer-rediscovery.** Run libFuzzer against `fuzz_webp_decode_vuln` for up to 24 CPU-hours on small valid WebP seeds (publicly available WebP test vectors). Goal: rediscover the bug class via fuzzing, recording wall-clock time to first crash.
2. For every crash file, run it against `fuzz_webp_decode_fix`. The patched build must NOT crash on any of the inputs. This is the patch-verification check.
3. Record:
   - The minimal crashing input (bytes + hex-dump + structure annotation)
   - ASAN report (full stack)
   - Time to first crash for the fuzzer-rediscovery path
   - SHA-256 of the input

Acceptance: `make reprochain-reproduce` runs both harnesses against the corpus and asserts (a) every input crashes the vulnerable build with `heap-buffer-overflow`, (b) no input crashes the patched build, (c) all outputs are deterministic across re-runs.

`[DECIDE]` Whether to also run the harness under MemorySanitizer or only ASAN. Default: ASAN only for primary, MSAN as a future extension.

### 4.4 Phase A3 — Confirm the fix and bound the claims

Goal: produce a clear, written technical analysis of the bug, suitable for inclusion in the AegisGraph evidence package.

Tasks:

1. `reprochain/analysis/CVE-2023-4863.md`: a 3-5 page writeup containing:
   - Vulnerability summary (where in the code, what the invariant violation is)
   - The vulnerable function annotated with line-by-line commentary
   - The fix annotated similarly
   - The reproduction recipe (build, run, expected output)
   - The bound on the claim: we are reproducing a publicly-disclosed and patched bug in an isolated harness; this work makes no claim about exploitability in any specific application, nor about user impact, nor about any vendor.
2. Pull the upstream commit message and CVE record into the writeup as primary references.

Acceptance: Writeup is committed, referenced from the evidence record (Phase A6), and reviewed internally for any language that overclaims.

### 4.5 Phase A4 — Static reachability in Signal Android

Goal: produce an automated, reproducible static reachability report from "inbound media handler" to "libwebp call site (or transitive)" in Signal Android.

Tasks:

1. Build a CodeQL database for Signal Android at the v0.3 pinned commit `1043851423b3034728b09d4a1991608d49205963`. Use `codeql/java-queries` as the base pack.
2. Write CodeQL queries (in `extraction/codeql/queries/`) that:
   - **Q-A4-1:** Find all entry points where inbound message media is dispatched to a decoder. Heuristic: parameters whose source is a `MmsAttachment`/`Attachment`/`SignalServiceAttachment` instance flowing into Glide/`BitmapFactory`/`ImageDecoder`.
   - **Q-A4-2:** Find all native methods reachable from the entry points in Q-A4-1 (transitive call graph through public methods).
   - **Q-A4-3:** Find any `System.loadLibrary` calls that could load `libwebp` directly or via a wrapper.
3. Manually audit the results to determine whether libwebp is reached statically, dynamically through Glide → Skia → system libwebp, or only through the system image decoder. Document the path with source-anchor URLs at the pinned commit.
4. For Element X Android (pinned commit `54525d855e7fdb7104f28f6fa5016312d5a2e160`), do the equivalent. The image-loading library is Coil rather than Glide; the path is likely `Coil → Skia → system libwebp`.
5. Produce a structured "reachability report" per target: JSON document listing entry → intermediate → sink, each anchored to a source URL.

Acceptance: `make reprochain-map` runs CodeQL on both targets and produces `reprochain/mapping/{signal,element-x}.json` with at least one path from inbound-media to a libwebp-reachable native call. If the path is "indirect via system image decoder," that is documented honestly — not laundered into a direct call.

`[OPEN]` On modern Android, libwebp is loaded by the platform `ImageDecoder` framework rather than by the app directly. We may be able to demonstrate "the app's media path reaches the platform decoder, which delegates to libwebp" but not "the app links libwebp itself." That nuance is part of the writeup; do not paper over it.

### 4.6 Phase A5 — AegisGraph evidence record

Goal: produce a JSON evidence record per target that fits the AegisGraph schema (§8) and connects ReproChain to the existing v0.3 graph.

Each record includes:

- `id` (e.g., `SIG-REPROCHAIN-CVE-2023-4863`)
- `cve` reference + URL
- `path_class` = `media-handling`
- `entry_node` source anchor (the inbound MMS handler at pinned commit)
- `intermediate_nodes` ordered list with anchors (Glide/Coil dispatch, native bridge, etc.)
- `sink_node` (libwebp `BuildHuffmanTable`, anchored at vendored vulnerable commit)
- `evidence_refs` (CodeQL query IDs + raw output hashes; reachability report path)
- `score_vector` per the v0.3 model
- `validation_task` = `reprochain.harness.run`
- `claim_state` = `validation-tasked` or `accepted` depending on whether the harness confirmed the path
- `limitations` (the "indirect via platform decoder" note if applicable)
- `recommendation_refs` (e.g., `REC-MEDIA`, `REC-NATIVE-FFI`, `REC-DEPENDENCY`)

Acceptance: Both records validate against the schema. They are listed in the v0.3+ evidence index. The validator's safety scan passes (no overclaim language, no source redistribution).

### 4.7 Phase A6 — "Pre-disclosure simulation"

Goal: tell the story that AegisGraph would have surfaced this attack-surface evidence pre-disclosure, without claiming AegisGraph would have *found* the bug.

Tasks:

1. Reset the v0.3 evidence model to use only information available before September 2023 (no CVE reference, no fix commit, no public writeup).
2. Run the extraction (Workstream C) on Signal Android and Element X Android at commits dated before September 2023. Record what AegisGraph would have produced as the top-K graph paths for media handling, sorted by score vector.
3. Show that the libwebp-reachable path is in the top-K. Document the K and the score-vector breakdown.
4. Write a clear narrative in `reprochain/analysis/pre-disclosure-simulation.md` that explains:
   - What AegisGraph surfaces is *attack-surface evidence*, not vulnerability discovery.
   - Surfacing a parser path with high remote-reachability + parser-complexity + native-FFI scores does not equal finding the bug.
   - It does mean the path would have been on a fuzzing/audit shortlist.
   - This is the right honest claim. It is materially stronger than the v0.3 framing.

Acceptance: The pre-disclosure simulation is internally reviewed for overclaim language. The narrative survives the question "would you bet your reputation on this if challenged by a Project Zero engineer in the room?"

### 4.8 ReproChain deliverables summary

When all phases are complete:

- Vendored libwebp at vuln + fix commits.
- Two libfuzzer harnesses, both ASAN-instrumented.
- A reproducible crash corpus.
- Patch verification suite.
- Per-target static reachability reports (Signal, Element X).
- AegisGraph evidence records for both targets.
- A 3-5 page bug analysis writeup.
- A pre-disclosure simulation writeup.
- Everything regenerable from `make reproduce-reprochain`.

---

## 5. Workstream B — PolyDiff (differential parser fuzzing)

### 5.1 What PolyDiff actually does

PolyDiff takes a string (or byte sequence) representing a URL, IRI, or HTML document containing an OpenGraph metadata block, runs it through N parser implementations, normalizes each parser's output into a common fact-vector schema, compares the fact vectors, and flags cases where the parsers disagree in security-relevant ways.

It is not a generic fuzzer. The novelty is the fact-vector normalization plus the security-relevance triage. Without those two pieces, this is just `for parser in parsers: parser(input)` — which any undergrad can write.

### 5.2 Phase B1 — Parser inventory and selection

Goal: choose the parsers that PolyDiff will compare, with rationale documented.

Selected parsers (Phase 1 — URLs):

| ID | Parser | Runtime | Why |
|---|---|---|---|
| `jdk-uri` | `java.net.URI` | JVM 21 | Default Java URI parser; used by older Android code |
| `android-uri` | `android.net.Uri` | Android API 34 | The Android-specific parser; differs from JDK |
| `okhttp-httpurl` | `okhttp3.HttpUrl` | JVM via OkHttp 4.x | Used by Signal, Element, most modern Android networking |
| `rust-url` | `url` crate | Rust stable | Used by libsignal-rust and matrix-rust-sdk |
| `python-urllib` | `urllib.parse` | CPython 3.11 | Reference implementation, useful as oracle |
| `whatwg-url-py` | `whatwg-url` Python package | CPython 3.11 | WHATWG-spec-compliant; differs from `urllib.parse` |
| `go-neturl` | `net/url` | Go 1.22 | Useful third reference |
| `libcurl` | `curl_url_*` API | C via ctypes | What native code paths actually use |

Phase 2 — OpenGraph/HTML metadata extractors (after Phase 1 ships):

| ID | Parser | Runtime | Why |
|---|---|---|---|
| `jsoup` | `org.jsoup` | JVM | Used in many Android link-preview pipelines |
| `lxml-py` | `lxml.html` | CPython | A reference parser |
| `gumbo-c` | `gumbo-parser` | C | Native HTML5 parser |
| `fast-html-parser-rs` | `tl` crate | Rust | A common Rust HTML parser |

`[DECIDE]` Whether to include `WebKit/Blink`-style parsers via headless browser. Probably not in Phase 1 — heavy infrastructure; defer.

### 5.3 Phase B2 — Wrapper harness design

Each parser runs as a standalone subprocess that reads input on stdin and emits a fact-vector on stdout as one line of JSON. This subprocess pattern keeps each parser in its native runtime without forcing JVM/CPython/Rust interop.

Skeleton (per parser):

```
polydiff/parsers/<parser-id>/
├── README.md         # which parser version, how to build
├── Dockerfile        # reproducible runtime
├── wrapper.{ext}     # the actual wrapper code
└── test_basic.sh     # smoke test
```

Wrapper contract:

- Reads up to 64 KiB from stdin (the candidate input).
- Attempts to parse.
- Emits exactly one JSON object on stdout with the fact-vector (§5.4).
- On parse failure, emits a fact-vector with `{"parsed": false, "error_class": "..."}` and exits 0. Crashes are exit non-zero and are treated as findings.
- Time-budget: 100 ms per input, enforced by the orchestrator with `SIGKILL` on timeout.

This deliberate process-per-input is slow (a couple thousand inputs per CPU-second), but it gives total isolation between runs and lets us catch crashes as findings rather than infrastructure failures. We optimize later via persistent worker mode if needed.

### 5.4 Phase B3 — Fact-vector schema

The fact-vector is the common representation that lets us compare parsers that have very different APIs. It is *the* core technical artifact of PolyDiff. Spec:

```json
{
  "parsed": true,
  "scheme": "https",
  "scheme_lowercased": "https",
  "userinfo_present": false,
  "userinfo_raw": null,
  "username": null,
  "password_present": false,
  "host_raw": "example.com",
  "host_lowercased": "example.com",
  "host_decoded": "example.com",
  "host_is_ip_literal": false,
  "host_is_ipv4": false,
  "host_is_ipv6": false,
  "host_is_ipvFuture": false,
  "host_is_loopback": false,
  "host_is_private_or_link_local": false,
  "host_has_idn": false,
  "host_punycode": null,
  "port_present": false,
  "port_value": null,
  "port_default_inferred": 443,
  "path_raw": "/foo/bar",
  "path_normalized": "/foo/bar",
  "path_traversal_resolved": false,
  "query_raw": null,
  "query_pairs": [],
  "fragment_raw": null,
  "percent_decoding_applied_in_host": false,
  "percent_decoding_applied_in_path": false,
  "trailing_slash_normalized": false,
  "leading_zeroes_in_octets_stripped": false,
  "tab_or_newline_stripped": false,
  "backslash_treated_as_slash": false,
  "control_chars_in_host_rejected": null,
  "scheme_authority_separator_strict": null,
  "raw_serialized": "https://example.com/foo/bar",
  "errors": [],
  "warnings": []
}
```

Every field above is a known axis on which URL parsers historically disagree. The complete list of fields is the result of mining the public corpus of URL-parser bug reports; we expect the list to grow during Phase B5 as fuzzing surfaces new axes.

For OpenGraph (Phase 2), there will be a sibling fact-vector schema covering: which `<meta>` tags are extracted, what URL is treated as the canonical OpenGraph image URL, whether HTML entities are decoded before URL parsing, etc.

### 5.5 Phase B4 — Disagreement detector

Given N fact-vectors from N parsers on the same input, the detector emits zero or more `Disagreement` records. A `Disagreement` is a tuple (input, axis, parser_A, parser_B, value_A, value_B).

The detector runs in two passes:

1. **Pairwise.** For every (parser_A, parser_B) pair, compare every axis. Emit a Disagreement on every mismatch. This is O(P² × A) where P is parsers and A is axes; with our P≤8 and A≈40, this is fine.
2. **Cluster.** Group parsers by fact-vector value on each axis. Axes where there are ≥2 distinct values across the parser set become "axis hot-spots." A hot-spot summary is emitted for every input that has any.

Acceptance: Given 10 hand-crafted inputs known to produce 5 disagreements on `host_lowercased` between `jdk-uri` and `okhttp-httpurl`, the detector emits exactly those 5 disagreements (no more, no less).

### 5.6 Phase B5 — Security-relevance classifier

This is where PolyDiff stops being a generic differential tester and becomes an SMA-aware tool.

Given a `Disagreement`, the classifier maps it to zero or more `SecurityRelevance` tags. The classifier is rule-based, not ML — every rule is auditable.

Initial rule set:

| Rule ID | Disagreement axis | Trigger | Tag |
|---|---|---|---|
| SR-HOST-MISMATCH | `host_lowercased` differs | Both parsers consider input parseable; hosts differ | `origin-confusion` |
| SR-LOOPBACK-DISAGREE | `host_is_loopback` differs | One parser thinks the host is loopback, another doesn't | `ssrf-loopback-bypass` |
| SR-PRIVATE-DISAGREE | `host_is_private_or_link_local` differs | Same idea, RFC 1918 / link-local | `ssrf-private-network` |
| SR-IDN-DISAGREE | `host_has_idn` differs OR `host_punycode` differs | Mixed handling of internationalized domains | `idn-spoof` |
| SR-USERINFO-DISAGREE | `userinfo_present` differs | One parser sees `user:pass@`, another folds it into the host | `userinfo-host-confusion` |
| SR-PATH-TRAVERSAL | `path_traversal_resolved` differs | One parser resolves `..`, another doesn't | `path-traversal` |
| SR-PERCENT-DECODE-HOST | `percent_decoding_applied_in_host` differs | One parser percent-decodes the host pre-parse, another doesn't | `host-injection` |
| SR-CONTROL-CHAR | `control_chars_in_host_rejected` differs | One parser rejects, another silently strips | `header-injection` |
| SR-BACKSLASH | `backslash_treated_as_slash` differs | Classic IE-vs-everyone-else | `path-confusion` |
| SR-PARSED-DIFFERS | `parsed` differs | One parser accepts, another rejects | `gating-bypass` |
| SR-SCHEME-AUTHORITY | `scheme_authority_separator_strict` differs | Various `https:foo` vs `https://foo` cases | `scheme-confusion` |

The classifier emits a `Finding` record per Disagreement that has ≥1 `SecurityRelevance` tag. Findings without tags are still recorded (as `Disagreement` records) but not surfaced in the triage view.

Acceptance: For a fixed corpus of 100 known-disagreement inputs (the regression set in §5.7), the classifier produces the expected `SecurityRelevance` tags as documented in `polydiff/regression/expected.json`.

### 5.7 Phase B6 — Regression set (the credibility anchor)

Goal: assemble a public corpus of historical URL-parser disagreement bugs that PolyDiff must rediscover from cold.

The regression set contains 30+ historical cases sourced from public CVEs, public bug reports, and academic literature. Each case is a directory:

```
polydiff/regression/cases/<id>/
├── input              # raw bytes
├── description.md     # what the disagreement is, who reported it
├── expected.json      # which parsers should disagree on which axes
└── reference.url      # primary public reference
```

Initial cases (to be expanded):

- The Snyk URL-parser confusion cases from their 2022 study (multiple)
- The okhttp `HttpUrl` vs `java.net.URI` userinfo cases
- Orange Tsai's SSRF / proxy-confusion examples
- The `urllib` vs `urllib3` host-resolution differences in Python pre-3.10
- The Node `url` vs `whatwg-url` legacy cases
- Specific Chromium URL bugs that affected SMA WebView use (research these)

Acceptance: Running `make polydiff-regression` produces a report showing PolyDiff catches ≥3 cases as `Finding` records (this is Tier-P1 from §2.3). Bonus credit for catching ≥80% of the corpus.

### 5.8 Phase B7 — Fuzzer driver

Goal: actually generate new inputs and find new disagreements.

Architecture:

- The mutator is libfuzzer-style structure-aware mutation (or honggfuzz). It mutates seed inputs drawn from the regression corpus plus a small handcrafted seed set of "interesting" URLs.
- The runner takes mutated inputs, runs all parsers on each, runs the disagreement detector, and persists every input that produced ≥1 Disagreement to a corpus directory.
- A coverage-style heuristic: an input is "interesting" if it produces a Disagreement on an axis that no prior input in the corpus produced. New-axis hits are prioritized.
- Run budget: configurable; default is 1 CPU-hour per workstream invocation in CI, 24 CPU-hours for local dev runs.

Acceptance: A 1-hour CI run on the regression seed set produces ≥10 new Disagreement records that are not in the regression set. (This is a low bar; in practice we expect hundreds.)

### 5.9 Phase B8 — Triage and reporting

Goal: turn the firehose of Disagreement records into a small set of vetted Findings suitable for the AegisGraph evidence package.

Tasks:

1. A deduplication pass that clusters Disagreements by (axis, parser_pair, error-class) and picks a minimal exemplar per cluster.
2. A human-in-the-loop triage interface (CLI or simple HTML viewer) that shows: the input, the fact-vectors, the rule-classifier output, and a comment field. The triager assigns one of: `confirmed-security`, `theoretical-only`, `infrastructure-bug`, `parser-design-difference-not-bug`, `dupe`.
3. For every `confirmed-security` Finding, generate an AegisGraph evidence record (§8).
4. For every `theoretical-only` Finding, record it but do not surface in the proposal-facing report.

Acceptance: At Tier-P2, ≥1 `confirmed-security` Finding exists outside the regression set. At Tier-P3, ≥1 such Finding warrants disclosure under the policy in §9.

### 5.10 Phase B9 — Map disagreements back to SMA codepaths

Goal: connect PolyDiff's library-level findings to actual SMA application code.

For each `confirmed-security` Finding, identify whether the affected parser is on a reachable path in Signal Android or Element X Android (using the extraction graph from Workstream C). If yes, the AegisGraph evidence record carries that reachability info. If no, the Finding is recorded as "library-level only, not currently reachable in tracked targets."

This is the bridge that turns PolyDiff from "we wrote a differential URL fuzzer" into "we found N disagreements in parsers reachable from inbound link previews in two real SMAs." That second framing is what makes ASEMA reviewers stop scrolling.

### 5.11 PolyDiff deliverables summary

When all phases are complete:

- 8 URL parser wrappers (Phase 1) plus 4 OpenGraph parsers (Phase 2 stretch).
- Fact-vector schema (~40 axes for URLs, schema for OpenGraph).
- Disagreement detector + classifier.
- Regression corpus of 30+ historical bugs with expected outcomes.
- Fuzzer driver with coverage-by-axis heuristic.
- Triage interface.
- AegisGraph evidence records for every `confirmed-security` Finding.
- Reachability map showing which Findings are reachable from Signal/Element-X inbound flows.
- Documentation of any new disagreements that warrant disclosure.

---

## 6. Workstream C — Real Automated Extraction

### 6.1 Why this exists

The v0.3 evidence has two fatal weaknesses that this workstream fixes:

1. The graph threads are hand-curated. A reviewer who clones the repo cannot regenerate them. This kills the reproducibility story.
2. The SOTA matrix has CodeQL and MobSF as "not run." This kills the credibility story.

Workstream C makes the graph extraction automated and the baseline tools actually run.

### 6.2 Phase C1 — CodeQL queries

Build a query pack (`extraction/codeql/queries/`) for SMA-relevant patterns. Initial query set:

- `entry-point-intent.ql` — Find every Android `Activity`/`Service`/`BroadcastReceiver`/`ContentProvider` whose intent filter accepts an external scheme.
- `inbound-message-handler.ql` — Find handlers that take inbound message bodies, attachments, or sync events.
- `link-preview-fetch.ql` — Find functions that take a URL parameter, fetch it, and process the response.
- `qr-handler.ql` — Find code paths that consume QR-decoded payloads.
- `media-decoder-entry.ql` — Find calls into Glide/Coil/`BitmapFactory`/`ImageDecoder`.
- `native-method-with-tainted-input.ql` — Find `native` methods whose parameters originate from network/IPC sources.
- `device-linking-flow.ql` — Find code paths that bind a new device to the user's account.
- `key-storage-access.ql` — Find access to secure storage (KeyStore, encrypted SharedPrefs, Realm encryption keys).

Each query produces SARIF; SARIF is normalized into the evidence graph by an adapter (`extraction/adapters/codeql_to_graph.py`).

Acceptance: `make extract-signal` runs the full query pack against Signal Android at the pinned commit, produces a graph in the AegisGraph schema, and the graph is checked into the evidence package.

### 6.3 Phase C2 — Semgrep ruleset

Semgrep is faster but less precise than CodeQL. Use it for:

- Detection of well-known anti-patterns (e.g., `WebView.setJavaScriptEnabled(true)` in a WebView that loads remote content)
- Quick survey of which third-party SDKs are in use
- Filtering CodeQL results

Build `extraction/semgrep/rules/` with at least:

- `webview-misconfig.yml`
- `unsafe-deeplink-handler.yml`
- `tainted-jni-bridge.yml`
- `permissive-intent-filter.yml`

Acceptance: `make extract-semgrep` runs over both targets, produces normalized findings in the evidence graph.

### 6.4 Phase C3 — MobSF integration (done properly)

Problem with the v0.3 framing: MobSF needs an APK, not source. We have public source, not APKs.

Two options:

- **Option C3-A:** Build the APK from source for each target and run MobSF against it. This is complex (needs full Android build environment) but is the right answer.
- **Option C3-B:** Pull the latest public release APK from F-Droid (Element X is on F-Droid; Signal is harder — Signal's official APKs are signed-and-distributed but not on F-Droid; APKMirror has them).

`[DECIDE]` Build from source (C3-A) or use distributed APKs (C3-B). Default: C3-B for Element X (F-Droid), C3-A for Signal (or skip Signal MobSF for v1 and add later). Document the asymmetry.

The MobSF run produces a JSON report; an adapter (`extraction/adapters/mobsf_to_graph.py`) folds the relevant findings into the graph.

Acceptance: `make extract-mobsf` runs MobSF in Docker, produces normalized graph entries for at least one target.

### 6.5 Phase C4 — Manifest analyzer

Parse `AndroidManifest.xml` from each target source tree. Emit:

- All exported components (activities, services, providers, receivers)
- Intent filters with their schemes/hosts/path patterns
- All declared permissions
- All native libraries declared

This replaces the v0.3 hand-counted "55 intent filters; 29 scheme/host entries" with an automated analysis whose output anyone can regenerate. Code lives in `extraction/manifest/`.

Acceptance: `make extract-manifest` produces a JSON report per target, byte-identical across runs.

### 6.6 Phase C5 — Graph assembler

Take the outputs of C1-C4 plus the existing v0.3 hand-curated threads, and assemble them into a single AegisGraph evidence graph per target. Resolve identity (the same source location appearing in CodeQL output and Semgrep output should appear once in the graph), score every path, and emit the v1 evidence record.

Acceptance: `make extract` produces `extraction/output/{signal,element-x}/graph.json` that validates against the schema (§8). Re-running produces a byte-identical graph (modulo timestamps).

---

## 7. Workstream D — SMABench Made Real

### 7.1 Ring 1 — Synthetic harnesses with actual code

The v0.3 release describes Ring 1 fixtures but doesn't ship them. Workstream D ships them. Initial fixtures:

- `smabench/ring1/url-corpus/` — A generator script (`generate.py`) that produces a synthetic corpus of URLs covering: redirects (to private IPs, to localhost, looped), oversized HTML responses, content-type drift, IDN edge cases, percent-encoding edge cases, OpenGraph metadata edge cases. Produces 10k inputs in <1 minute. Hashable.
- `smabench/ring1/qr-corpus/` — A generator that produces QR payloads representing valid, malformed, expired, replayed, and wrong-account device-linking states. Output is a directory of `.png`s plus a `meta.json` file describing what each represents.
- `smabench/ring1/deeplink-corpus/` — A generator that produces synthetic deep-link strings for both `signal://` and `matrix://`/`element://`/`https://matrix.to` schemes, including edge cases.
- `smabench/ring1/sync-corpus/` — Synthetic Matrix sync responses and Signal sync envelopes. Useful for testing sync state handling without a real homeserver.
- `smabench/ring1/pq-corpus/` — Synthetic PQXDH and Megolm key-rotation traces.

Each fixture has a `harness.py` that consumes the corpus and runs it against the unit-of-test (a parser, a state machine, a fuzzer harness).

### 7.2 Ring 2 — Wired to extraction

Ring 2 is just the Workstream C output, packaged for benchmark consumption. No new code needed beyond pointing at the extraction artifacts.

### 7.3 Ring 3 — Placeholder, future

A stub directory with a README explaining what would go here under written authorization. Not built in this phase.

### 7.4 Bench runner

`smabench/run.py` is the orchestrator. It:

- Runs Ring 1 fixtures against the relevant ReproChain and PolyDiff harnesses.
- Runs Ring 2 extraction against the pinned target commits.
- Aggregates results into `smabench/results/<date>/results.json`.
- Compares against the previous run's results and emits a delta report (regressions / improvements).

CI runs the bench weekly. Results are committed back to the repo. Drift is visible.

---

## 8. Cross-cutting — Evidence Schema, Audit, and Safety

### 8.1 Evidence schema (`schema/evidence.schema.json`)

Canonical schema for AegisGraph evidence records. Every record has:

- `id` — stable identifier
- `version` — schema version (currently `v1.0`, supersedes v0.3)
- `target` — which SMA codebase, with pinned commit
- `path_class` — one of the eight ASEMA classes
- `nodes` — ordered list of (node-type, source-anchor, evidence-source) tuples
- `edges` — relationships between nodes
- `score_vector` — the ten-dimensional score with sum check
- `claim_state` — observed | anchored | scored | validation-tasked | reviewed | accepted | limited | retired
- `validation_task` — reference to a runnable harness, with input + expected output
- `evidence_refs` — list of (tool, version, command, output-hash) tuples
- `recommendation_refs` — list of recommendation IDs
- `limitations` — free text, mandatory, never empty
- `provenance` — who/what/when produced this record
- `safety_flags` — populated by the safety scanner

`[DECIDE]` Whether to migrate the v0.3 records to v1.0 schema or maintain both. Default: maintain both; v1.0 is additive.

### 8.2 Recommendation contract

Unchanged from v0.3 in spirit. Every recommendation record has the nine fields v0.3 specified (id, category, graph-refs, evidence-refs, source-anchors, implementation-hint, expected-effect, residual-risk, effort-estimate, standards-mapping-caveat). New addition: every recommendation produced by ReproChain or PolyDiff carries a `derived_from_finding` field referencing the underlying finding ID.

### 8.3 Safety scanner

The validator's safety scanner expands beyond v0.3's checks. New rules:

- No raw bytes from any in-repo PolyDiff input that triggers a crash on a maintained library that has not been disclosed and patched. (I.e., we don't ship 0day in the repo. If PolyDiff finds something disclosable, it goes in a private branch until the disclosure timeline closes.)
- No vendored libwebp commits beyond what's needed for ReproChain (vuln + fix). No carrying-forward of unpatched code.
- No SMA target source redistribution. Only anchors and derived measurements.
- Standards-mapping language must include a caveat in every recommendation record that touches MASVS/MASTG/SSDF/SBOM/VEX/SARIF.

### 8.4 Audit trail

Every evidence record carries a hash chain back to its inputs. The chain is verified by the validator. Tampering with intermediate state breaks the chain.

This is the one place where the existing Forge OS prior work plausibly transfers in: the hash-chain audit pattern is reusable for evidence provenance.

### 8.5 Disclosure policy (because PolyDiff might find live bugs)

If PolyDiff produces a `confirmed-security` Finding affecting a parser used in maintained software:

1. The Finding goes to a private repo branch, not main.
2. The maintainer is contacted via their published security disclosure channel.
3. We follow the project's disclosure timeline (90 days default, extensible with maintainer agreement).
4. After patch ships, the Finding is moved to main and the AegisGraph evidence record is publicized.
5. We do not weaponize. We do not publish PoCs that go beyond the minimum needed to demonstrate the disagreement.
6. We coordinate with downstream consumers (Signal, Element/Matrix, etc.) if the finding affects them.

`[DECIDE]` Who owns the disclosure relationship. Default: PI (Dr. Waweru) is the named contact; counsel is consulted before any disclosure.

---

## 9. Phase Plan and Milestones

### 9.1 Phase ordering

The ordering below maximizes morale (early concrete demo) and minimizes blocking.

**Phase 0 — Infrastructure (Week 1-2)**
- Repo scaffold, dev container, CI, Makefile.
- Tooling baseline (CodeQL, MobSF in Docker, Semgrep, Clang+libfuzzer).
- Schema v1.0 draft.
- Validator stubs in Python.

**Phase 1 — ReproChain crash reproduction (Week 3-5)**
- Phase A1 (vendor + harness)
- Phase A2 (reproduce crash)
- Phase A3 (fix verification + writeup)
- Demo-ready: `make reproduce-reprochain` produces ASAN crash on vuln, clean on fix.

**Phase 2 — Extraction skeleton (Week 6-9)**
- Phase C1 (CodeQL queries — initial set)
- Phase C2 (Semgrep ruleset)
- Phase C4 (manifest analyzer)
- Phase C5 (graph assembler v1)
- Demo-ready: `make extract` produces a real automated graph for both targets.

**Phase 3 — ReproChain integration (Week 10-12)**
- Phase A4 (static reachability in both targets, using Phase 2's extraction)
- Phase A5 (evidence records)
- Phase A6 (pre-disclosure simulation)
- Demo-ready: end-to-end story from inbound media to libwebp call site, scored, with simulation writeup.

**Phase 4 — PolyDiff foundation (Week 13-17)**
- Phase B1 (parser inventory)
- Phase B2 (wrapper harnesses)
- Phase B3 (fact-vector schema)
- Phase B4 (disagreement detector)
- Demo-ready: `polydiff run --input '...'` produces fact-vectors and disagreements for hand-fed inputs.

**Phase 5 — PolyDiff regression and fuzzer (Week 18-22)**
- Phase B5 (security-relevance classifier)
- Phase B6 (regression set assembled)
- Phase B7 (fuzzer driver)
- Demo-ready: `make polydiff-regression` rediscovers ≥3 known historical disagreements from cold.

**Phase 6 — PolyDiff triage and integration (Week 23-26)**
- Phase B8 (triage)
- Phase B9 (reachability mapping)
- Phase C3 (MobSF integration)
- Phase D (SMABench harnesses)
- Demo-ready: full pipeline; proposal-quality artifacts.

**Phase 7 — Hardening and proposal-facing artifacts (Week 27+)**
- The 20-page DARPA white paper compression.
- The 15-slide deck.
- Final SOTA matrix.
- Stretch goals from §1.4 if time permits.

The above is a 6-month aggressive plan for one engineer working full-time, with Claude Code as the collaborator. Realistic timelines double or triple that.

### 9.2 Definition-of-done gates per phase

Each phase has a hard gate before the next phase begins:

- All phase deliverables committed and visible in the repo.
- CI green on the pinned dev container.
- Validator passes on whatever evidence the phase produced.
- A 1-page status note in `docs/decision-log/` summarizing what was done, what was learned, what changed in the spec.

If a phase misses its gate, the spec gets updated to reflect reality. The spec serves the work, not the other way around.

### 9.3 Demo points (for internal review and eventual proposal use)

- After Phase 1: ReproChain crash demo (5 minutes, screen recording).
- After Phase 3: ReproChain end-to-end demo (10 minutes, includes pre-disclosure simulation).
- After Phase 5: PolyDiff regression demo (10 minutes, shows rediscovery).
- After Phase 6: Full pipeline demo (15 minutes — what the DARPA Month-14 demo looks like in miniature).

---

## 10. Risks, Open Questions, and Decisions Only the Human Can Make

### 10.1 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| libwebp reproduction harder than expected (build issues, ASAN flake, can't construct the input from spec) | Medium | High | Two parallel approaches in Phase A2 (handcrafted + fuzzer); allocate 24 CPU-hours for fuzzer fallback |
| CodeQL query precision is poor on large Android codebases | Medium | Medium | Start with small query slices; iterate; treat manual annotations as first-class |
| MobSF integration is too fragile for CI | Medium | Low | Keep MobSF runs out of CI critical path; optional in `make extract` |
| PolyDiff produces too many low-relevance disagreements; signal-to-noise destroys triage | High | Medium | Strict classifier rules; aggressive deduplication; human-in-the-loop triage |
| PolyDiff produces an actual live bug we have to disclose responsibly | Medium | Medium | Disclosure policy in §8.5 |
| Project takes longer than the proposal deadline allows | Very High | High | Phase 1-3 alone is enough for a credible feasibility story; Phase 4-6 makes it groundbreaking. Triage by priority. |
| Reviewers see "we built parser fuzzer #11000" rather than novel contribution | Medium | High | The novelty is the fact-vector schema + SMA-reachability mapping; lead with that in writeups |
| Forge OS prior-work continues to look bolted-on | Medium | Low | Limit Forge OS to one specific reuse: hash-chain audit for evidence provenance. Drop the other claims. |

### 10.2 Open questions that block work

- `[OPEN]` Exact pre-fix and post-fix commit hashes for libwebp CVE-2023-4863. Resolves in Phase A1.
- `[OPEN]` Whether Signal Android invokes libwebp directly or only via Android's `ImageDecoder`. Resolves in Phase A4. The honest answer goes in the writeup either way.
- `[OPEN]` What URL-parser bug history is publicly documented well enough to seed the regression set with 30+ cases. Resolves in Phase B6.
- `[OPEN]` Whether MobSF supports running against AAB or only APK, given Element X's distribution. Resolves in Phase C3.

### 10.3 Decisions only you can make

- `[DECIDE]` Project owner / PI sign-off on the libwebp choice over ForcedEntry.
- `[DECIDE]` Project owner / PI sign-off on URL-parser differential fuzzing over MLS lifecycle work.
- `[DECIDE]` Disclosure-handling owner if PolyDiff produces a live finding.
- `[DECIDE]` Whether the codebase ships under an Apache 2.0 / MIT license or stays private until proposal submission.
- `[DECIDE]` Whether to build a Signal Android APK from source for MobSF (C3-A) or use distributed APKs (C3-B).
- `[DECIDE]` Whether to keep the v0.3 Node validator alongside the new Python validator.
- `[DECIDE]` Whether to migrate v0.3 records to v1.0 schema or maintain both.
- `[DECIDE]` Whether to extend ReproChain to a second CVE (CVE-2019-11932 WhatsApp GIF) as a stretch.
- `[DECIDE]` Whether to extend PolyDiff to OpenGraph parsers in Phase 2.
- `[DECIDE]` Budget cap for CI compute (fuzzer hours per week). Default: 100 CPU-hours/week, ~$50/week on a small cloud bill.

### 10.4 What this spec does not address (and why)

- **Publication strategy.** Out of scope per project owner.
- **External validator engagement.** Out of scope per project owner.
- **Phase III commercialization plan.** Lives in the master proposal, not in technical spec.
- **Compliance / DSIP volumes.** Human-owned proposal-prep work.
- **Team CVs and qualifications writeups.** Proposal-prep work.
- **iOS targets.** Future work; intentionally Android-only here to keep scope tractable and aligned with v0.3 corpus.
- **Group-state rollback / MLS lifecycle work.** Considered and rejected for this spec; revisit after the parser-focused work ships.

---

## 11. Appendix — File-by-file checklist for Phase 0

To get unstuck on day one, here is the literal first commit:

```
aegisgraph/
├── README.md                                  # 1 paragraph: what this is
├── SPEC.md                                    # this document
├── LICENSE                                    # [DECIDE] before first push
├── Makefile                                   # phony targets only, errors on undefined
├── .github/workflows/ci.yml                   # check: docker build, make tooling, lint
├── devcontainer/
│   ├── Dockerfile                             # pinned base image, all tooling
│   └── post-create.sh                         # codeql/mobsf/semgrep installs
├── docs/
│   ├── decision-log/0001-libwebp-over-forcedentry.md
│   ├── decision-log/0002-polydiff-over-mls.md
│   └── adr-template.md
├── schema/
│   └── evidence.schema.json                   # v1.0 draft
└── validator/
    └── validate_evidence.py                   # stub: load schema, validate one file
```

Everything else is added as the corresponding phase begins.

---

*End of specification. This is v0.1 of the Tier-3 spec. Update freely.*
