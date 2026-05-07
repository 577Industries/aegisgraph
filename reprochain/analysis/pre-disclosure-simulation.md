# Pre-disclosure simulation: what AegisGraph would have done before
# CVE-2023-4863 became public

The simulation question for the AegisGraph Tier 3 research repo is
narrow and honest: **given pre-disclosure access only to public
target source anchors and the AegisGraph parser-risk model, would the
system have elevated the libwebp media-decode path as a high-priority
fuzzing/audit target before September 2023?**

The answer this artifact supports is **yes — for prioritization, not
for discovery.** AegisGraph's score vector for the media_decode path
puts it firmly in the high-priority band. That would have caused a
human auditor or fuzz-budget allocator to pull the libwebp surface
forward in their queue. AegisGraph would NOT have, on its own, found
the specific `BuildHuffmanTable` OOB write — discovery requires
either a fuzzer with the right harness shape (which is what
`reprochain/harness/fuzz_webp_decode.cc` becomes after a build) or a
source auditor doing the kind of trace through Huffman-code-length
parsing that the public disclosure ultimately came from.

The distinction matters because the public claim is bounded. We are
not claiming that AegisGraph predicts unknown CVEs. We are claiming
that AegisGraph reduces the search space a researcher must cover by
giving them a defensible, scored prioritization across a target's
attack surfaces.

## The score vector

The media_decode path in `aegisgraph/score.py::media_parser_score`
emits the following vector:

| Dimension              | Weight | Rationale                                                                                                  |
|------------------------|-------:|------------------------------------------------------------------------------------------------------------|
| `remote_reachability`  |  0.90  | An MMS/RCS attachment, an inbound chat message media, or a link preview can carry a WebP payload.          |
| `attacker_control`     |  0.90  | The bitstream is fully attacker-shaped; only RIFF/VP8L/VP8X header invariants must hold.                   |
| `parser_complexity`    |  0.80  | Lossless WebP (VP8L) carries inline Huffman tables, color caches, transforms — high state-machine depth.   |
| `native_boundary`      |  0.80  | libwebp is C; Android's BitmapFactory hands off to system C codec; classic JNI-managed memory boundary.    |
| `auth_boundary`        |  0.60  | Decoded before the user accepts the message in many UIs (auto-thumbnail, preview).                         |
| `privilege_impact`     |  0.70  | Code execution in the messaging app's process or, on Android, in the system codec helper process.         |
| `exploit_history`      |  0.90  | libwebp + image-codec parsers have a long CVE history (2018 BAUMI, 2020 buffer overflow, 2023 this one).   |
| `mitigation_strength`  |  0.50  | ASLR + CFI mitigate but don't eliminate; Huffman-table corruption gives fine attacker control over writes. |
| `observability`        |  0.40  | Decode failures are silent in production; few apps surface anything diagnostic to user telemetry.          |
| `confidence`           |  0.55  | Static-only at extraction time; we do not yet have CodeQL-derived dataflow.                                |

**Total: 7.05 / 10**

The threshold for "high-priority audit target" in the AegisGraph
scoring rubric (per the integration stream's `validator/score.py`
binding) is **6.5**. The media_decode score of 7.05 clears that
threshold by about half a point. Concretely, this means the path
shows up in the top tranche of any reachability sweep AegisGraph
emits — above link_parser_score (6.20), above sync_state, and
roughly tied with native_boundary.

The two dimensions that drag this score down are `confidence` (0.55)
and `observability` (0.40). Both are honest: the v0.3 extraction is
anchor-only, not CodeQL-derived, and the deployed apps don't surface
WebP-decode telemetry to anyone who could use it for triage. Both
would improve in later phases — `confidence` with CodeQL-anchored
SARIF nodes, `observability` with the public-target diagnostic sweep
proposed in the SMA bench (`smabench/`).

## Acceptable output

The AegisGraph evidence record for this surface (the records this
stream emits at `reprochain/mapping/{signal,element-x}.json`)
contains:

* **Scored reachability**: the score vector above, with each
  dimension justified in the limitations field.
* **Explicit limitations**: the Android platform-decoder indirection
  is called out by name (`android.graphics.ImageDecoder` /
  `BitmapFactory.decodeStream` mediating to a system codec linked
  against libwebp). The fact that the app code does NOT call libwebp
  directly is the load-bearing limitation that prevents over-claiming.
* **Source anchors**: target-pin commits (`signal=1043851`,
  `element-x=91d265e6`) plus the libwebp vendored vuln pin
  (`7ba44f8`). When CodeQL-derived extraction lands these anchors get
  upgraded to `tree/<sha>/path/to/File.kt#L<line>` URLs.
* **Validation tasks**: `make reprochain-run`, with an expected
  output that names the differential the harness must demonstrate
  (`fuzz_webp_decode_vuln crash_count > 0; fuzz_webp_decode_fix
  crash_count == 0`).

## Unacceptable output (out of scope by design)

Things this stream's records **never** carry, by design:

* Raw exploit inputs. The handcrafted seed corpus stays gitignored;
  only sha256 + structural one-liners are committed. No payload
  bytes, no working proof-of-concept material.
* Live-target interaction. Neither the harness nor the orchestrator
  reaches network targets, accesses production accounts, or probes
  deployed messaging apps. Everything reads from local files.
* Claims that static analysis alone proves a target vulnerability.
  AegisGraph's `claim_state` for these records caps at `reviewed` —
  meaning the prioritization claim has been validated by the harness
  differential — not at `accepted`, which would imply behavioral
  reproduction.
* Disclosure-sensitive reproducer material in public exports. The
  `validator/sanitize_check.py` gate plus the
  `release_classification` machinery in `aegisgraph/evidence.py` keep
  records flagged with restricted patterns from being sealed for
  public release.

## Summary

AegisGraph's parser-risk score for the libwebp media-decode path
clears the high-priority-audit threshold (7.05 vs. 6.5). A pre-2023
AegisGraph deployment would have queued this surface for fuzzing
ahead of, e.g., the link-preview parser path on the same targets. It
would not have discovered CVE-2023-4863 on its own; that bug was
found upstream by Citizen Lab + Apple + Google in the course of
investigating an in-the-wild exploitation chain. AegisGraph's role
is to make sure the surface where that bug lived would have been at
the front of the audit queue — and to back that prioritization with
a reproducible harness that confirms, after the fact, that the
fragility class was real.
