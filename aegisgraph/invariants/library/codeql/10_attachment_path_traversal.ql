/**
 * @id aegisgraph/inv-10-attachment-path-traversal
 * @name InvariantCheck INV-10: Attachment filename path traversal
 * @description Attachment filenames received from inbound messages must
 *              not flow into java.io.File / FileOutputStream
 *              constructor / java.nio.file.Files.write without passing
 *              through a path-canonicalization barrier
 *              (File.getCanonicalPath, Path.normalize() followed by a
 *              startsWith prefix check against the attachment-directory
 *              root). A filename containing `..`, an absolute path, or
 *              NUL bytes can escape the attachment directory and
 *              overwrite app private storage including key material.
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id-mapping INV-10
 * @tags security
 *       external-input
 *       file-system
 *       aegisgraph-invariantcheck
 *       mastg-storage-2
 *       ssdf-pw-5-1
 */

/*
 * Encoding notes:
 *
 *   Sources: attachment-name getters on inbound messages — Attachment,
 *            MediaItem, DocumentMessage, AttachmentPointer.
 *
 *   Sinks: the write itself — FileOutputStream / FileWriter constructor,
 *          Files.write / writeString / newOutputStream / newBufferedWriter
 *          / createFile (the Path written), Files.copy / move (the target).
 *          Building a File / Path from the name is a taint STEP, not a
 *          sink (ADR 0022): one finding per planted flow, and the
 *          canonicalisation barrier that callers apply to that object
 *          covers the write that follows.
 *
 *   Barriers: canonicalise-then-check — File.getCanonicalPath/File or
 *             Path.normalize/toAbsolutePath/toRealPath whose result flows
 *             into a String/Path startsWith or equals; or any helper
 *             method named isPathSafe / stripPathTraversal /
 *             sanitizeAttachmentName / ensureInsideRoot (…); or
 *             Pattern.matches against a safe-filename regex.
 *
 * TODO[ground-truth-pass]: Signal-android Attachment.getFileName and
 * Element-X MediaItem.getOriginalName placeholder method names are
 * structural — the M7-GT pass pins them against the actual class names
 * in the anchored commits.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import AttachmentPathTraversalFlow::PathGraph

/**
 * Sources: attachment-name getters on inbound message payloads.
 */
class AttachmentNameSource extends DataFlow::Node {
  AttachmentNameSource() {
    // Attachment.getFileName / Attachment.getDisplayName etc. We match
    // by method name + a *Attachment / *MediaItem / *Document /
    // *AttachmentPointer declaring type so we don't catch unrelated
    // getFileName() calls (e.g. on uploaded local files).
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*Attachment.*|.*MediaItem.*|.*Document.*|.*AttachmentPointer.*|.*FileMessage.*|.*ImageMessage.*|.*VideoMessage.*") and
      mc.getMethod()
          .hasName([
            "getFileName", "getDisplayName", "getOriginalName",
            "getName", "getCaption", "getTitle", "getPath",
            "filename", "fileName"
          ]) and
      this.asExpr() = mc
    )
    or
    // Top-of-handler parameters typed as an attachment-bearing payload.
    exists(Parameter p |
      p.getType()
          .(RefType)
          .getName()
          .regexpMatch(".*Attachment$|.*AttachmentPointer$|.*MediaItem$|.*DocumentMessage$") and
      this.asExpr() = p.getAnAccess()
    )
  }
}

/**
 * Sinks: the file-write surfaces themselves.
 *
 * Constructing a java.io.File / java.nio.file.Path from the attacker-
 * controlled name is NOT a sink — nothing has touched the file system
 * yet, and the canonicalisation barrier is normally applied to exactly
 * that object before the write. Those constructions are modelled as
 * taint steps below, so the finding lands on the write (one report per
 * planted flow) instead of once on the File and again on the stream.
 */
class FileWriteSink extends DataFlow::Node {
  FileWriteSink() {
    // new java.io.FileOutputStream(file_or_path) / new FileWriter(...).
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", ["FileOutputStream", "FileWriter"]) and
      this.asExpr() = cc.getArgument(0)
    )
    or
    // java.nio.file.Files write surfaces — the Path being written.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
      mc.getMethod()
          .hasName(["write", "writeString", "newOutputStream", "newBufferedWriter", "createFile"]) and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // Files.copy / Files.move — the *target* path (arg 1) is where a
    // traversal name escapes the attachment directory.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
      mc.getMethod().hasName(["copy", "move"]) and
      this.asExpr() = mc.getArgument(1)
    )
  }
}

/**
 * Path-construction steps: the name taints the File / Path built from it.
 */
predicate pathConstructionStep(DataFlow::Node pred, DataFlow::Node succ) {
  // new java.io.File(parent, name) / new File(name).
  exists(ConstructorCall cc |
    cc.getConstructedType().hasQualifiedName("java.io", "File") and
    pred.asExpr() = cc.getAnArgument() and
    succ.asExpr() = cc
  )
  or
  // Paths.get(name...) and Path.of(name...).
  exists(MethodCall mc |
    mc.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", ["Paths", "Path"]) and
    mc.getMethod().hasName(["get", "of"]) and
    pred.asExpr() = mc.getAnArgument() and
    succ.asExpr() = mc
  )
  or
  // Path.resolve(name) / resolveSibling — java.nio and okio alike.
  exists(MethodCall mc |
    mc.getMethod().getDeclaringType().hasQualifiedName(["java.nio.file", "okio"], "Path") and
    mc.getMethod().hasName(["resolve", "resolveSibling"]) and
    pred.asExpr() = [mc.getQualifier(), mc.getArgument(0)] and
    succ.asExpr() = mc
  )
  or
  // File.toPath() / Path.toFile() carry the taint across the two APIs.
  exists(MethodCall mc |
    mc.getMethod().getDeclaringType().hasQualifiedName(["java.io", "java.nio.file"], ["File", "Path"]) and
    mc.getMethod().hasName(["toPath", "toFile"]) and
    pred.asExpr() = mc.getQualifier() and
    succ.asExpr() = mc
  )
}

/**
 * A canonicalising call: File.getCanonicalPath/getCanonicalFile or
 * Path.normalize/toAbsolutePath/toRealPath.
 */
private predicate canonicalisingCall(MethodCall mc) {
  mc.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and
  mc.getMethod().hasName(["getCanonicalPath", "getCanonicalFile"])
  or
  mc.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
  mc.getMethod().hasName(["normalize", "toAbsolutePath", "toRealPath"])
}

/**
 * A containment check: String/Path.startsWith or equals on the
 * canonical form, i.e. the comparison against the attachment-root prefix.
 */
private predicate containmentCheck(MethodCall chk) {
  chk.getMethod().hasName(["startsWith", "equals"]) and
  chk.getMethod()
      .getDeclaringType()
      .hasQualifiedName(["java.lang", "java.nio.file"], ["String", "Path"])
}

/**
 * Barriers: canonicalise-THEN-check, or an explicit sanitiser helper.
 *
 * Canonicalising alone is not a barrier — `getCanonicalPath()` whose
 * result is never compared against the attachment root removes nothing.
 * Likewise a bare `startsWith` on an un-canonicalised name is not a
 * barrier (`"../x".startsWith("..")` tells you nothing about the root).
 * The value is safe only when the canonical form flows into a
 * containment check; the barrier is placed on the canonicalised object
 * so every later use of it (the actual write) is covered.
 */
class PathCanonicalizationBarrier extends DataFlow::Node {
  PathCanonicalizationBarrier() {
    exists(MethodCall canon, MethodCall chk |
      canonicalisingCall(canon) and
      containmentCheck(chk) and
      DataFlow::localExprFlow(canon, [chk.getQualifier(), chk.getAnArgument()]) and
      this.asExpr() = [canon, canon.getQualifier()]
    )
    or
    // Sanitizer helper methods.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "isWithinAttachmentDir", "isPathSafe", "stripPathTraversal",
            "sanitizeAttachmentName", "ensureInsideRoot",
            "normalizeAttachmentPath", "rejectTraversal",
            "checkPathContainment", "validateAttachmentName"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // Pattern.matches against a safe-filename regex.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
      mc.getMethod().hasName("matches") and
      this.asExpr() = mc.getArgument(1)
    )
  }
}

/**
 * Configuration: taint flow from attachment-name getters to file-write
 * sinks, with canonicalization helpers as barriers.
 */
module AttachmentPathTraversalConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof AttachmentNameSource }

  predicate isSink(DataFlow::Node snk) { snk instanceof FileWriteSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof PathCanonicalizationBarrier
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    pathConstructionStep(pred, succ)
  }
}

module AttachmentPathTraversalFlow =
  TaintTracking::Global<AttachmentPathTraversalConfig>;

from
  AttachmentPathTraversalFlow::PathNode source,
  AttachmentPathTraversalFlow::PathNode sink
where AttachmentPathTraversalFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-10: Attachment filename from $@ reaches file-write sink without traversing a path-canonicalization or containment barrier.",
  source.getNode(), "this source"
