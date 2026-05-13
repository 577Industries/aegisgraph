/**
 * @id aegisgraph/inv-14-backup-blob-unauthenticated
 * @name InvariantCheck INV-14: Backup blob without MAC or signature (STUB — M7 deliverable)
 * @description Backup write and restore paths must not produce or
 *              consume backup blobs without a MAC (HMAC-SHA256 or KMAC)
 *              or signature (Ed25519, ECDSA-P256) covering the entire
 *              blob; an unauthenticated backup is a tampering surface
 *              because an attacker with backup-file access can modify
 *              message history, group state, or key references on disk
 *              and have them silently accepted on restore.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id-mapping INV-14
 * @tags security
 *       cryptography
 *       integrity
 *       aegisgraph-invariantcheck
 *       mastg-storage-8
 *       ssdf-pw-6-1
 *       stub
 */

/*
 * ─────────────────────────────────────────────────────────────────────
 * STUB QUERY — NOT YET FULLY ENCODED (M7 deliverable)
 * ─────────────────────────────────────────────────────────────────────
 *
 * This file is committed so the M5.3 manifest entry for INV-14 resolves
 * to a real file on disk. The full encoding is scheduled for M7.
 *
 * Intended encoding sketch (drives the M7 work):
 *
 *   This is a two-direction invariant — both backup-write and
 *   backup-restore must be authenticated.
 *
 *   Sources A (backup-write entry points):
 *     - Methods named *createBackup / *writeBackup / *exportBackup /
 *       *serializeBackup / *toBackupBlob
 *     - Calls on classes named *BackupExporter / *BackupSerializer
 *
 *   Sinks A (network / disk emission of backup blobs):
 *     - OutputStream.write where the qualifier is a
 *       *BackupOutputStream
 *     - okhttp3.RequestBody from the backup-blob bytes
 *     - File / FileOutputStream / Files.write applied to a path
 *       containing "backup" in its name
 *
 *   Barriers A (MAC / signature wrap on write):
 *     - HMac.doFinal / KMac.doFinal applied to the blob bytes before
 *       emission
 *     - java.security.Signature.sign on the blob
 *     - Methods named ["macBackup", "signBackup",
 *       "wrapBackupWithSignature", "computeBackupMac"]
 *
 *   Sources B (backup-restore entry points):
 *     - Methods named *restoreBackup / *importBackup / *parseBackup /
 *       *deserializeBackup / *fromBackupBlob
 *
 *   Sinks B (state-restore from backup blobs):
 *     - DatabaseHelper.bulkInsert with rows extracted from the blob
 *     - KeyStore.setKeyEntry with keys extracted from the blob
 *     - GroupDatabase.applyBackupGroupState
 *
 *   Barriers B (MAC / signature verification on restore):
 *     - HMac.doFinal + constant-time comparison against the carried MAC
 *     - java.security.Signature.verify on the blob
 *     - Methods named ["verifyBackupMac", "verifyBackupSignature",
 *       "authenticateBackup"]
 *
 *   Configuration:
 *     The query emits two separate findings if either direction is
 *     missing authentication. We expect two TaintTracking::Configuration
 *     modules:
 *
 *     class BackupWriteUnauthConfig extends
 *       TaintTracking::Configuration { ... }
 *     class BackupRestoreUnauthConfig extends
 *       TaintTracking::Configuration { ... }
 *
 *     The select clause is the union of both.
 *
 *   Select clause emits: sink,
 *     "INV-14: Backup write at $@ emits blob without MAC/signature
 *      barrier."
 *   or
 *     "INV-14: Backup restore at $@ accepts blob without MAC/signature
 *      verification barrier."
 *
 *   Ground truth (planned):
 *     - demo-vulnerable-app: 2 violations (one unauth write, one unauth
 *       restore).
 *     - Signal Android / Element X: unknown.
 *
 * Until this stub is fleshed out, the runner produces an empty SARIF
 * result set for INV-14.
 *
 * See aegisgraph/invariants/manifest.json :: INV-14 for the canonical
 * statement, rationale, MASTG-STORAGE-8 / SSDF PW.6.1 mappings.
 *
 * TODO[M7]: Fully encode this query per the spec above. Pay attention
 * to the wrapped-cipher case: a backup encrypted with AES-GCM is
 * authenticated by the GCM tag itself — that is an acceptable
 * authentication mode and should be modeled as a barrier (look for
 * Cipher.getInstance("AES/GCM/NoPadding") on the backup path).
 * ─────────────────────────────────────────────────────────────────────
 */

import java

// Trivially-empty query so codeql syntactically accepts the file while
// the stub is in place. select clause produces no results.
from Method m
where none()
select m, "INV-14 stub — see comment block in this file for the M7 encoding plan."
