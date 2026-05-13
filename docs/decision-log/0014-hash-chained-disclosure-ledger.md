# 0014 Hash-Chained Coordinated-Disclosure Ledger

Status: **accepted** (disclosure stream owns enforcement; integration stream merges the schema + scaffold).

## Context

Engine 6 (Coordinated Disclosure) needs a tamper-evident record of every disclosure event (vendor contact, embargo set/extended, CVE request/assignment, public disclosure) so that:

- A reviewer can audit the full lifecycle of any finding from `reviewed → reviewed_embargoed → disclosed_public`.
- An external party can verify that the disclosed timeline matches what 577 Industries committed to (CERT/CC-style 90-day window).
- The DARPA M14 demo can show "we filed this CVE, the ledger says when and by whom" as a structured artifact rather than a screenshot.

We already have hash-chain primitives in `aegisgraph/hashchain.py` (`record_payload`, `hash_record`, `attach_hash_chain`, `verify_hash_chain`) with the `json-v1-sorted-no-hash-chain` canonicalization. They were built for individual evidence records; this ADR extends their use to a *sequence* of records (the ledger).

## Decision

The Coordinated-Disclosure ledger is an **append-only JSONL file** at `aegisgraph/disclosure/ledger.jsonl`. Each line is one event conforming to `schema/disclosure-event.schema.json` (introduced in ADR-0013), finalized with the same hash-chain primitives the rest of the evidence graph uses.

### Storage format

- **One event per line.** Each line is a single JSON object with no inner newlines (canonical JSON via `aegisgraph.io.canonical_json`).
- **Hash chain across lines.** The first line's `hash_chain.previous_hash` is `null`. Every subsequent line's `previous_hash` equals the prior line's `record_hash`. The chain is verifiable by `aegisgraph.disclosure.ledger.verify_chain()`.
- **Canonicalization:** `json-v1-sorted-no-hash-chain` (unchanged from `aegisgraph/hashchain.py:CANONICALIZATION`).
- **No truncation, no rewrite.** Adding an event appends one line. Correcting a prior event means appending a `retired` event referencing the bad entry; the bad entry stays on the chain. This is the same discipline as a Git commit log.

### Why JSONL not a database

- **Human-diffable in git.** A reviewer can `git log -p aegisgraph/disclosure/ledger.jsonl` and see every disclosure event the project has touched.
- **Survives offline ops (Forge OS pattern).** No DB server required; runs on the same minimal devcontainer that runs every other AegisGraph engine.
- **Single-writer (PI).** Makes locking trivial: the disclosure CLI acquires a file lock, reads the last line, computes the next hash, appends. No concurrent-write story to design.
- **Reproducible.** `make disclose-status` can be run by any reviewer in the devcontainer and produces the same output bit-for-bit.
- **Write rate is <5 entries/month.** A DB would buy us nothing at this scale and would add a backup story, a recovery story, and a runtime dependency.

### Signing (deferred)

The schema field `signature` is present and defaulted to `null` in v0.4. PKI integration is deferred to v1.0 (or to Forge-OS-bundled deployment). Until then, ledger integrity rests on:

1. The hash chain (tampering with line N invalidates lines N..end).
2. Branch protection on `stream/disclosure` (force-push prohibited; ledger lives in git history).
3. Weekly mirror to a write-once object store (S3 with object lock or equivalent) — operational, not in the schema.

### Append-only contract enforced in code

- `aegisgraph/disclosure/ledger.py:append(event)` is the only supported write path. It (a) reads the last line, (b) extracts `record_hash`, (c) calls `attach_hash_chain(event, previous_hash=last_record_hash)`, (d) appends one canonical line.
- `aegisgraph/disclosure/ledger.py:verify_chain()` walks the file line-by-line and asserts every link.
- `aegisgraph/disclosure/ledger.py:read_all()` returns the list of events for downstream consumers (export gate, workbench).

### What the ledger contains

Each event has the fields defined in `schema/disclosure-event.schema.json`:

- `entry_id` (pattern `AG-DISC-YYYYMMDD-XXXX`)
- `finding_id` (the evidence record this event is about)
- `engine_origin` (which engine found it)
- `event_type` (vendor_contacted, vendor_acknowledged, embargo_set, embargo_extended, vendor_patched, cve_requested, cve_assigned, cve_published, embargo_expired, disclosure_public, escalated_cert_cc, retired, vendor_no_response_30d)
- `timestamp` (ISO-8601 UTC)
- `actor` (577_industries_pi, 577_industries_eng, vendor_security_team, cert_cc, mitre, public, embargo_timer)
- `vendor_contact` (email or org id — **redacted in public exports** per sanitize-check Rule 7 extension)
- `embargo_until` (date or null)
- `embargo_days` (per-finding override of the 90-day default)
- `cve_id` (null until assigned)
- `public_disclosure_url` (null until public)
- `payload_hash_only` (SHA-256 of associated finding payload; never the payload itself)
- `notes_hash` (SHA-256 of private notes stored outside the ledger; e.g., counsel review notes)
- `signature` (always `null` in v0.4)
- `provenance` + `safety_flags` + `hash_chain` (same shape as every other evidence record)

### Public export redaction

Per ADR-0021 (validator hardening) extension, `validator/sanitize_check.py` adds **Rule 7**: a disclosure_event record in a public export must have:

- `event_type ∈ {cve_assigned, cve_published, disclosure_public}`
- A populated `public_disclosure_url` for `disclosure_public`
- `vendor_contact` REDACTED to organization-level identifier (e.g., `"signal_foundation"` not `"signal-security@signal.org"`)
- `notes_hash` REDACTED to `null`

Records with `event_type ∈ {vendor_contacted, vendor_acknowledged, embargo_set, embargo_extended, vendor_patched, cve_requested, escalated_cert_cc}` are PRIVATE-ONLY and never appear in public exports.

## Verification

- `aegisgraph/disclosure/ledger.py:verify_chain()` returns the list of errors per ledger line; the empty list is success.
- A new test `tests/disclosure/test_ledger_hash_chain_tamper_evident.py` asserts: (a) appending two events produces a verifiable two-line chain, (b) mutating any byte in line 1 causes `verify_chain` to flag line 1's record_hash mismatch, (c) inserting a line out of order breaks the chain.
- `make disclose-status` summarizes the ledger in a human-readable form.
- The GitHub Actions workflow `.github/workflows/embargo-tick.yml` runs daily, walks the ledger, and emits new events when embargo boundaries (day 7, 14, 30, 60, 90) are crossed.

## Why this matters operationally

The DARPA reviewer's mental question is: "Show me you actually filed a CVE." The answer is: "Here is `aegisgraph/disclosure/ledger.jsonl`, here is the CVE assignment line, here is the `verify_chain()` output proving the lineage from finding → vendor contact → embargo → CVE → public." That is a more credible deliverable than a screenshot of an NVD entry — because the ledger ties the CVE to a specific evidence record with a specific SHA-256, originating in a specific engine on a specific commit.

## Out of scope

- CVE assignment via MITRE / Chrome CNA / GitHub Security Advisories — those are operational paths (see `aegisgraph/disclosure/templates/cve_request.j2`), not ADR decisions.
- The 90-day embargo timer schedule itself — lives in `aegisgraph/disclosure/pipeline/embargo_timer.py` + the GH Actions cron.
- Cryptographic signing — deferred to v1.0.
- The specific first-disclosure target — emerges from PolyDiff Extended / HarnessGen triage output; the plan recommends a libwebp upstream path but this ADR does not pre-commit to a target.

## Related

- 0006 — disclosure ownership (the PI-as-named-owner decision this ledger records)
- 0010 — schema additive-only (disclosure-event schema is governed by 0010)
- 0011 — public-export human gate (the gate that sanitize_check Rule 7 enforces on the ledger)
- 0013 — schema v2 discovery-graph extension (introduces `disclosure_event` node + `reviewed_embargoed`/`disclosed_public` claim states)
- 0021 — validator hardening (sanitize_check Rule 7 added by this ADR's enforcement)

## Proposal claims

- C-NEW-CD — Coordinated Disclosure (Engine 6) — anchored by this ADR's ledger format.
- C-DISC-V1 through C-DISC-V5 — individual disclosure event claims as ledger entries land.
- C-EVAL-1 — public-package verification extends to include ledger validation.
