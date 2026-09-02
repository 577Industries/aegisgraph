# 0026 — INV-04 ground truth counts the by-design overlap with INV-13

Status: accepted (2026-09-02)

## Context

`04_device_link_no_kex.ql` deliberately includes QR-scan result strings
(ML Kit `Barcode.getRawValue`, ZXing `Result.getText`) among its sources.
Its encoding notes say so: *"the QR-camera surface is primarily INV-13's
responsibility but is also matched here for defense-in-depth — duplicate
findings are deduplicated by the consolidator using location keys."*

The fixture author planted **one** INV-04 violation (`DeviceLinkNoKex.java`)
and recorded `expected_violations: 1`. But the fixture app also contains
`QrPayloadUnverified.kt`, planted for INV-13, whose line 20
(`store.storeSession(payload)` straight from `barcode.rawValue`) is, under
INV-04's own definition, a device-provisioning call with no KEX round-trip.
Once the traced build extracts Kotlin, INV-04 correctly reports it too:
the first traced measurement gave **2**, and after the INV-04 model fixes
of this calibration pass (member steps, control-flow guard) it still gives
2 — `DeviceLinkNoKex.java:18` and `QrPayloadUnverified.kt:20`.

Two ways to reconcile: narrow the query (drop the QR sources) or correct
the ground truth. The query's overlap is a documented design choice — a
QR-provisioned session without a KEX round-trip *is* an INV-04 violation,
whatever else it is — and the consolidator already de-duplicates the
shared location across invariants. The ground truth was written without
accounting for it.

## Decision

- `manifest.json` INV-04 `demo-vulnerable-app` `expected_violations`: **1 → 2**,
  with a `note` on the entry: one planted (`DeviceLinkNoKex.java`) plus one
  by-design overlap (`QrPayloadUnverified.kt:20`, also INV-13 violation 1).
- The fixture README table shows the overlap; the "exactly one invariant per
  file" sentence becomes "planted for exactly one invariant; INV-04's QR
  sources overlap INV-13 by design". Planted total stays 28; measured total
  for the twelve CodeQL queries is 29 because of this one shared location.
- Buildless cannot extract the Kotlin half of that count, so INV-04 becomes a
  `kotlin-extraction` xfail **(1)** in the buildless table and is absent from
  the traced table. No fixture line changes.

## Consequences

- The count now states what the query is specified to find. Anyone
  narrowing INV-04's sources later must lower this number in the same
  change (the strict contract will demand it).
- Cross-invariant duplicates remain the consolidator's job
  (`aegisgraph/invariants/runner/sarif_consolidator.py`, location keys).

## Related

- 0022–0025 — the rest of the 2026-09-02 calibration pass
- `04_device_link_no_kex.ql` encoding notes; `13_qr_payload_unverified_binding.ql`
