# 0008 PolyDiff URL-parser differential over MLS lifecycle modeling

Status: accepted (placeholder; polydiff-core stream will refine).

## Decision

Select URL-parser cross-implementation differential analysis as the
initial PolyDiff contribution. NOT MLS (RFC 9420) lifecycle modeling.

## Rationale

| Axis | URL-parser differential | MLS lifecycle modeling |
|---|---|---|
| Team depth | Standard library / parser engineering background; no special expertise required | Protocol cryptography research; the team currently lacks deep MLS group-key management depth |
| Reachability in SMAs | URL parsing happens on every link preview, every deep link, every QR-device-link redirect. Universal across Signal, Element-X, WhatsApp, Telegram, etc. | MLS group-state lifecycle is shipping in Element-X but not in Signal; cross-SMA differential is structurally limited |
| Empirical grounding | Snyk 2022 "URL parser inconsistencies" study (12 parsers, 25+ historical CVEs); whatwg-url, Node's URL, Python's urllib, Go's net/url, libcurl, Java's URI all have documented disagreements | MLS handshake / commit fault-tolerance has limited public differential data; most analysis is formal-methods, not corpus-based |
| Composition with the rest of the platform | Fact vectors compose directly with extraction's link_preview / deeplink / qr_device_link path classes; smabench corpora drop into polydiff fuzzers | MLS analysis would need a separate harness, separate scoring, and produces evidence in a distinct shape |
| Safety posture | Differential outputs are normalized records (tool, parser, input_canonicalized, output_canonicalized). No raw byte payloads needed for evidence; safety scanner stays clean | MLS analysis tends to produce sequence-level traces that would need careful sanitization before public export |

## Constraints carried into polydiff-core

- The fact-vector shape (`schema/fact-vector.schema.json`) is the v1.0
  baseline. If PolyDiff-core needs new fields it MUST follow the
  additive policy in `0010-schema-additive-only.md` (or propose a v2
  schema with its own ADR).
- Per-parser corpora live under `polydiff/parsers/<parser-name>/` and
  carry only normalized inputs (canonicalized URL strings, no
  authentication tokens, no live-target captures).
- Polydiff fact vectors reference smabench corpus IDs as upstream
  evidence. Merge order requires smabench-harness to land first.

## Out of scope

- This ADR does not block future MLS work. If a separate stream proposes
  an MLS lifecycle module after Phase II kickoff, it gets its own ADR
  and its own evidence schema. PolyDiff is specifically about parser
  disagreement, not protocol-level analysis.
- This ADR does not assert which parser is "correct." Differential
  evidence reports the disagreement. Validation tasks pick a normative
  reference (typically the WHATWG URL spec) and report deviations from
  it; no parser is condemned without a passing validation_task.

## What flips this decision

1. Snyk-style URL-parser inconsistency corpora become unavailable
   (extremely unlikely given multiple independent public sources).
2. Polydiff-core demonstrates that the URL parser corpus is too small
   to produce statistically meaningful results — at which point we
   broaden to additional parsers (HTML, JSON, deep-link routing) within
   the same disagreement framework.
3. The team gains MLS protocol-cryptography depth and proposes adding
   MLS as a SECOND polydiff target (additive, not replacement).

## Related

- 0004 — PolyDiff selection (Phase-0 placeholder this ADR refines)
- 0010 — schema additive-only policy (governs the URL-parser fact-vector evolution)
- 0020 — fact-vector v2 migration (concrete additive evolution this ADR anticipated)

## Proposal claims

- C-NEW-PD — PolyDiff rediscovery target.
- C-ABS-5 — measured-output framing relies on this scope.
- C-V03-5 — supplements Semgrep zero-finding baseline with PolyDiff regression-set anchor.
