# 0022 — INV-10: the write is the sink, path construction is a step

Status: accepted (2026-09-02)

## Context

INV-10 (attachment filename path traversal) planted two violations in
`tests/fixtures/demo-vulnerable-app/.../AttachmentPathTraversal.java` and
one clean control. The first honest CodeQL measurement (buildless database,
bundle 2.26.4) returned **5** results and the count was recorded as a
`precision-calibration` xfail:

| Line | Statement | Why it fired |
| --- | --- | --- |
| 24 | `new File(root, name)` | File constructor argument was a sink |
| 25 | `new FileOutputStream(out)` | the write — planted violation 1 |
| 33 | `Paths.get("/var/attachments/" + name)` | `Paths.get` argument was a sink |
| 34 | `Files.write(p, data)` | the write — planted violation 2 |
| 40 | `new File(root, name)` in `writeAttachmentSafe` | File constructor fired before the canonicalisation on line 41 |

Two of the five were the planted flows reported twice (once on the path
object, once on the write), and one was the clean control's own `new File`,
which no barrier can protect because it necessarily precedes
`getCanonicalPath()` on that object.

## Decision

1. **Sinks are the write surfaces only**: `FileOutputStream` / `FileWriter`
   constructors, `Files.write` / `writeString` / `newOutputStream` /
   `newBufferedWriter` / `createFile` (the Path argument), and `Files.copy` /
   `move` (the *target* argument). Constructing a `java.io.File` or a
   `java.nio.file.Path` from the name touches nothing on disk.
2. **Path construction is an explicit taint step** (`pathConstructionStep`):
   `new File(..)`, `Paths.get` / `Path.of`, `Path.resolve` / `resolveSibling`
   (java.nio and okio), `File.toPath` / `Path.toFile`. The finding therefore
   lands on the write and is reported once per flow.
3. **Canonicalise-then-check is the barrier**: `getCanonicalPath` /
   `getCanonicalFile` / `normalize` / `toAbsolutePath` / `toRealPath` is a
   barrier only when its result flows into a `startsWith` / `equals`
   containment check. A bare canonicalisation (never compared to the root)
   and a bare `startsWith` on an un-canonicalised name (`"../x".startsWith("..")`)
   are no longer barriers. The barrier is placed on the canonicalised object,
   so every later use of it — the write — is covered through the use-use
   chain. The named sanitiser helpers and `Pattern.matches` are unchanged.

## Consequences

- Measured locally after the change (same bundle, same buildless database):
  **2** results — lines 25 and 34, exactly the planted violations; the safe
  control reports nothing. The `INV-10` entry leaves `GROUND_TRUTH_XFAIL_BY_MODE`
  for both modes (the strict contract would otherwise fail the run).
- A `new File(dir, attackerName)` that is handed to an *unmodelled* library
  method is no longer reported. That is a deliberate precision trade: the
  invariant statement in `manifest.json` names the write surfaces, not the
  File object, and the real-world false-positive rate of "any File built from
  a message field" would be high. Add the library method as a sink when a
  target surfaces one.
- No fixture line changed; `manifest.json` expected count (2) is unchanged.

## Related

- 0021 — validator hardening (the strict-xfail contract this measurement feeds)
- `tests/invariants/test_ground_truth_pass.py::GROUND_TRUTH_XFAIL_BY_MODE`
