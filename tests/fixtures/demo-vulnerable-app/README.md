# demo-vulnerable-app — synthetic ground-truth fixture

**Synthetic Android+Kotlin+Java fixture for AegisGraph InvariantCheck
library v3 (M7-GT-v3, Wave 8A).** Not based on any real product code.

Each source file under `src/main/java/com/example/demo/` is a small (<60
LoC) synthetic snippet planted for exactly one of the 15 InvariantCheck
invariants documented in `aegisgraph/invariants/manifest.json`. One
documented overlap exists: INV-04's QR-scan sources (defense-in-depth for
INV-13) also match `QrPayloadUnverified.kt:20`, so INV-04's count is 2
(ADR 0026). The shared "good" barrier helpers
under `fixtures/` (`Allowlist.java`, `KexCompletion.java`,
`PolicyChecker.java`) are referenced by some files to demonstrate the
barrier-present case alongside the violating case.

## Expected violation counts (mirrors manifest.json :: demo-vulnerable-app)

| File | Invariant | Expected violations |
| --- | --- | --- |
| `UrlFetchWithoutPolicy.java` | INV-01 | 3 |
| `NotificationLeak.java` | INV-02 | 2 |
| `GroupStateUnauth.kt` | INV-03 | 1 |
| `DeviceLinkNoKex.java` (+ overlap in `QrPayloadUnverified.kt`) | INV-04 | 2 |
| `KeyStorageNoKeystore.java` | INV-05 | 1 |
| `PqDowngrade.kt` | INV-06 | 1 |
| `AndroidManifest.xml` | INV-07 | 2 |
| `ClipboardPasteToSend.java` | INV-08 | 1 |
| `WebviewJsInterface.java` | INV-09 | 2 |
| `AttachmentPathTraversal.java` | INV-10 | 2 |
| `DeeplinkOpenRedirect.kt` | INV-11 | 3 |
| `MediaDecodeUnsanitized.java` | INV-12 | 3 |
| `QrPayloadUnverified.kt` | INV-13 | 2 |
| `BackupBlobUnauth.java` | INV-14 | 2 |
| `MetadataLeakOutsideEnvelope.kt` | INV-15 | 2 |

**Total**: 28 planted violations across 15 invariants (29 expected results,
counting the INV-04/INV-13 shared location once per query). What the
current toolchain actually measures is recorded per extraction mode in
`tests/invariants/test_ground_truth_pass.py::GROUND_TRUTH_XFAIL_BY_MODE`
(buildless Java-only database vs the traced java-kotlin build under
`../demo-vulnerable-app-traced/`). Invariants absent from a mode's table
reproduce exactly there; every entry present is an honest deviation (Kotlin
extraction, model or precision calibration) with its observed count and
reason. Fixture-line changes ship with an ADR in `docs/decision-log/`.

## Test harness

`tests/invariants/test_ground_truth_pass.py` parametrizes over all 15
invariants. For each:

* If the corresponding binary (`codeql` for CodeQL queries, `semgrep`
  for Semgrep rules) is absent, the test is skipped.
* Otherwise the test builds a CodeQL DB from this fixture (for CodeQL
  queries), or runs `semgrep --config=<rule> --json` against the fixture
  source files (for Semgrep rules), parses the SARIF / JSON output, and
  asserts that the violation count equals the manifest's
  `expected_violations` for the `demo-vulnerable-app` target.

The binary-present path is exercised by
`.github/workflows/invariants-ground-truth.yml` on the self-hosted
runner (T-M4.1).

## Honest scope

These files are intentionally tiny. They demonstrate the syntactic shape
of each invariant violation against real Android-framework / Java
standard-library APIs. They do not exercise framework lifecycle,
multi-file taint propagation across modules, or vendor-specific
abstractions (Signal libsignal `SessionStore`, Matrix android-sdk
`MXCryptoStore`, etc. are referenced via placeholder fully-qualified
names with `TODO[ground-truth-pass]` comments in the production CodeQL
queries).

The fixture is open-source and contains no reference to real Signal /
Element X / WhatsApp / Wire / Telegram source paths or class
hierarchies. All identifiers are `com.example.demo` or
`com.example.fixtures`.
