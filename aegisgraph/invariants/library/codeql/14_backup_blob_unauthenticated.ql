/**
 * @id aegisgraph/inv-14-backup-blob-unauthenticated
 * @name InvariantCheck INV-14: Backup blob without MAC or signature
 * @description Backup write and restore paths must not produce or
 *              consume backup blobs without a MAC (HMAC-SHA256 or KMAC)
 *              or signature (Ed25519, ECDSA-P256) covering the entire
 *              blob; an unauthenticated backup is a tampering surface
 *              because an attacker with backup-file access can modify
 *              message history, group state, or key references on disk
 *              and have them silently accepted on restore.
 *
 *              This is a two-direction invariant. We model both paths
 *              in a single configuration: the source set unions backup-
 *              write entry points (createBackup, writeBackup) and
 *              backup-restore entry points (restoreBackup, parseBackup);
 *              the sink set unions blob-emission sinks (OutputStream
 *              write, HTTP request body) and state-restore sinks
 *              (DatabaseHelper.bulkInsert, KeyStore.setKeyEntry).
 *              Either direction missing authentication produces a
 *              finding.
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id-mapping INV-14
 * @tags security
 *       cryptography
 *       integrity
 *       aegisgraph-invariantcheck
 *       mastg-storage-8
 *       ssdf-pw-6-1
 */

/*
 * Encoding notes:
 *
 *   Sources A (backup write): createBackup / writeBackup / exportBackup
 *            / serializeBackup / toBackupBlob method returns.
 *   Sources B (backup restore): restoreBackup / importBackup /
 *            parseBackup / deserializeBackup / fromBackupBlob returns.
 *
 *   Sinks A (network/disk emission): OutputStream.write where qualifier
 *          is a *BackupOutputStream, okhttp3.RequestBody.create on
 *          backup blob, FileOutputStream with "backup" in the path.
 *   Sinks B (state restore): DatabaseHelper.bulkInsert, KeyStore.
 *          setKeyEntry, GroupDatabase.applyBackupGroupState.
 *
 *   Barriers (both directions):
 *     - javax.crypto.Mac.doFinal (HMAC family) applied to the blob.
 *     - java.security.Signature.sign / Signature.verify on the blob.
 *     - javax.crypto.Cipher with AES/GCM/NoPadding — GCM tag provides
 *       authentication on the wrapped path.
 *     - Named helpers: macBackup, signBackup, verifyBackupMac,
 *       verifyBackupSignature, authenticateBackup.
 *
 * TODO[ground-truth-pass]: Signal-android and Element-X backup-
 * exporter / -importer class names are placeholders; the M7-GT pass
 * pins them against the anchored commits.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

/**
 * Sources: backup blob production AND consumption entry points.
 *
 * Unioned so the single configuration captures both directions of the
 * invariant. The select message disambiguates which direction matched.
 */
class BackupBlobSource extends DataFlow::Node {
  BackupBlobSource() {
    // Backup-write entry points (Source A).
    exists(MethodCall mc |
      mc.getMethod()
          .getName()
          .regexpMatch("(?i)(create|write|export|serialize|emit|build)(Backup|BackupBlob)") and
      this.asExpr() = mc
    )
    or
    // Backup-restore entry points (Source B).
    exists(MethodCall mc |
      mc.getMethod()
          .getName()
          .regexpMatch("(?i)(restore|import|parse|deserialize|read|load|from)(Backup|BackupBlob)") and
      this.asExpr() = mc
    )
    or
    // Methods declared on a *BackupExporter / *BackupSerializer /
    // *BackupImporter / *BackupDeserializer type.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*BackupExporter.*|.*BackupSerializer.*|.*BackupImporter.*|.*BackupDeserializer.*|.*BackupReader.*|.*BackupWriter.*") and
      this.asExpr() = mc
    )
    or
    // Top-of-handler parameters typed *BackupBlob / *BackupPayload.
    exists(Parameter p |
      p.getType()
          .(RefType)
          .getName()
          .regexpMatch(".*BackupBlob.*|.*BackupPayload.*|.*BackupEnvelope.*|.*BackupArchive.*") and
      this.asExpr() = p.getAnAccess()
    )
  }
}

/**
 * Sinks: blob-emission (Sink A) AND state-restore (Sink B).
 */
class BackupBlobSink extends DataFlow::Node {
  BackupBlobSink() {
    // Sink A: OutputStream.write where the qualifier name suggests a
    // backup-oriented stream.
    exists(MethodCall mc |
      mc.getMethod().hasName("write") and
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*BackupOutputStream.*|.*OutputStream") and
      (
        mc.getQualifier()
            .getType()
            .(RefType)
            .getName()
            .regexpMatch("(?i).*backup.*") or
        mc.getMethod()
            .getDeclaringType()
            .getName()
            .regexpMatch(".*BackupOutputStream.*")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // Sink A: okhttp3.RequestBody.create on backup bytes.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("okhttp3", "RequestBody") and
      mc.getMethod().hasName("create") and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // Sink A: FileOutputStream.write — captured when the file name
    // contains "backup" (best-effort heuristic).
    exists(ConstructorCall cc, MethodCall mc |
      cc.getConstructedType().hasQualifiedName("java.io", "FileOutputStream") and
      cc.getAnArgument().(StringLiteral).getValue().regexpMatch("(?i).*backup.*") and
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("java.io", "FileOutputStream") and
      mc.getMethod().hasName("write") and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // Sink B: DatabaseHelper.bulkInsert / Database.applyBackupGroupState.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "bulkInsert", "applyBackupGroupState",
            "restoreFromBackup", "applyBackupRows", "ingestBackup"
          ]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // Sink B: KeyStore.setKeyEntry with restored key material.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyStore") and
      mc.getMethod().hasName(["setKeyEntry", "setEntry"]) and
      this.asExpr() = mc.getAnArgument()
    )
  }
}

/**
 * Barriers: MAC / signature wrap on write, MAC / signature verify on
 * restore, and the AES-GCM-authenticated wrapped path.
 */
class BackupAuthenticationBarrier extends DataFlow::Node {
  BackupAuthenticationBarrier() {
    // HMAC family — javax.crypto.Mac.doFinal / Mac.update on the blob.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Mac") and
      mc.getMethod().hasName(["doFinal", "update", "init"]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // java.security.Signature — sign on write, verify on restore.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.security", "Signature") and
      mc.getMethod()
          .hasName(["sign", "verify", "update", "initSign", "initVerify"]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // AES-GCM wrapped path — Cipher.getInstance("AES/GCM/NoPadding")
    // provides authentication via the GCM tag. Match the Cipher object
    // initialization or its doFinal output.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
      mc.getMethod()
          .hasName(["doFinal", "update", "init", "getInstance"]) and
      // Restrict to GCM-mode ciphers via the algorithm-string literal.
      exists(MethodCall init, StringLiteral algo |
        init.getMethod()
            .getDeclaringType()
            .hasQualifiedName("javax.crypto", "Cipher") and
        init.getMethod().hasName("getInstance") and
        algo = init.getArgument(0) and
        algo.getValue().regexpMatch("(?i).*GCM.*|.*Poly1305.*|.*ChaCha20Poly1305.*")
      ) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // Named helper methods.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "macBackup", "signBackup", "wrapBackupWithSignature",
            "computeBackupMac", "verifyBackupMac",
            "verifyBackupSignature", "authenticateBackup",
            "verifyBackup", "checkBackupIntegrity"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
  }
}

/**
 * Configuration: taint flow from backup blob production / consumption
 * entry points to blob-emission / state-restore sinks, with MAC /
 * signature / AES-GCM barriers.
 */
module BackupBlobUnauthConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof BackupBlobSource }

  predicate isSink(DataFlow::Node snk) { snk instanceof BackupBlobSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof BackupAuthenticationBarrier
  }
}

module BackupBlobUnauthFlow = TaintTracking::Global<BackupBlobUnauthConfig>;

from BackupBlobUnauthFlow::PathNode source, BackupBlobUnauthFlow::PathNode sink
where BackupBlobUnauthFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-14: Backup blob from $@ reaches emission or state-restore sink without traversing a MAC, signature, or AEAD authentication barrier.",
  source.getNode(), "this source"
