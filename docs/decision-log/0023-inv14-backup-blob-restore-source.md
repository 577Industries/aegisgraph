# 0023 — INV-14: restore leg gets a backup-typed source; emission sink is any write

Status: accepted (2026-09-02)

## Context

INV-14 (backup blob without MAC/signature) planted two violations in
`BackupBlobUnauth.java` and measured **0** under both extraction modes. Both
misses were model/fixture mismatches, not extraction:

- **Violation 1** (`writeBackupUnsigned`): the source bound —
  `BackupSerializer.serialize()` matches the `*BackupSerializer*` type
  rule — but the emission sink required the *stream* to be backup-named
  (`*BackupOutputStream*`, or a `FileOutputStream` opened on a string
  literal containing "backup"). Real exporters write through a plain
  `FileOutputStream` or a socket; the stream's name carries no information.
- **Violation 2** (`readBackupUnverified`): the fixture filled a `byte[]`
  from a `FileInputStream` on a `File` parameter — nothing backup-typed
  anywhere on the source side — and `BackupRestorer.restore(blob)` was not
  among the restore sinks (`bulkInsert`, `applyBackupGroupState`,
  `restoreFromBackup`, `applyBackupRows`, `ingestBackup`).

## Decision

Query (`14_backup_blob_unauthenticated.ql`):

1. Emission sink A is **any** `OutputStream.write(bytes)` (declaring type a
   subtype of `java.io.OutputStream`) and `Files.write` / `writeString`
   (the bytes argument). The source side already restricts flows to blobs
   produced by backup writers, so the sink needs no name heuristic. The
   "backup" string-literal heuristic on `FileOutputStream` is removed as
   subsumed.
2. Restore sink B additionally accepts `restore` / `import` / `apply` /
   `ingest` / `load` (optionally suffixed `Backup` / `BackupBlob` /
   `BackupRows` / `BackupGroupState` / `FromBackup`) when the declaring type
   matches `*Backup(Restorer|Importer|Reader|Deserializer|Store|Manager)*`.
   The explicit name list is unchanged.

Fixture (`BackupBlobUnauth.java`, violation 2 only):

```java
// before
byte[] blob = new byte[(int) in.length()];
try (FileInputStream fis = new FileInputStream(in)) { fis.read(blob); }
restorer.restore(blob);
// after
byte[] blob = BackupReader.readBackup(in);
restorer.restore(blob);
```

plus the nested helper `BackupReader.readBackup(File)` and the dropped
`FileInputStream` import. The restore leg now starts at a backup-typed read,
which is the shape the invariant statement describes ("consume backup blobs
without a MAC"). The file stays under the 60-LoC budget (53 lines).

## Consequences

- Measured locally (buildless, bundle 2.26.4): **2** results — line 23
  (`fos.write(blob)`) and line 30 (`restorer.restore(blob)`). The clean
  control `writeBackupSigned` reports nothing: `PolicyChecker.verifyBackupMac(blob, mac)`
  is a named barrier on `blob`, and the MAC bytes come from a helper whose
  body returns a fresh array. `INV-14` leaves both xfail tables.
- Widening sink A means a backup blob written to *any* stream without
  authentication is a finding — that is the invariant. Flows that never
  start at a backup producer are unaffected because the source set is
  unchanged.
- `manifest.json` expected count (2) unchanged; violation 1 untouched.

## Related

- 0022 — INV-10 sink semantics (same calibration pass)
- `tests/invariants/test_ground_truth_pass.py::GROUND_TRUTH_XFAIL_BY_MODE`
