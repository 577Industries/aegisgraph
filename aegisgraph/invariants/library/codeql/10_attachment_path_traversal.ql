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
 *   Sinks: file-write surfaces — java.io.File constructor (name arg),
 *          FileOutputStream constructor, Files.write, Path.resolve.
 *
 *   Barriers: File.getCanonicalPath() followed by a prefix check,
 *             Path.normalize() + startsWith, or any helper method named
 *             isPathSafe / stripPathTraversal / sanitizeAttachmentName /
 *             ensureInsideRoot.
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
 * Sinks: file-write surfaces that consume the attacker-controlled name.
 */
class FileWriteSink extends DataFlow::Node {
  FileWriteSink() {
    // new java.io.File(parent, name) — the name argument (2-arg ctor).
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "File") and
      this.asExpr() = cc.getAnArgument()
    )
    or
    // new java.io.FileOutputStream(file_or_path).
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "FileOutputStream") and
      this.asExpr() = cc.getAnArgument()
    )
    or
    // java.nio.file.Files.write / Files.writeString — first arg is the
    // Path target.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
      mc.getMethod()
          .hasName([
            "write", "writeString", "newOutputStream", "createFile",
            "copy", "move"
          ]) and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // java.nio.file.Paths.get(name) — the name argument.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and
      mc.getMethod().hasName("get") and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // java.nio.file.Path.resolve(name) — the resolved name is taint.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
      mc.getMethod().hasName(["resolve", "resolveSibling"]) and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // okio.Path.resolve — same shape as java.nio.file.Path.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("okio", "Path") and
      mc.getMethod().hasName("resolve") and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

/**
 * Barriers: path-canonicalization and containment checks.
 */
class PathCanonicalizationBarrier extends DataFlow::Node {
  PathCanonicalizationBarrier() {
    // java.io.File.getCanonicalPath / getAbsolutePath — once a path is
    // canonicalized AND the calling code performs a startsWith check
    // against the attachment-root prefix, the value is safe. We model
    // the canonical helper itself as the barrier (the prefix-check
    // intent is assumed when callers use these methods on the same
    // value flow).
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and
      mc.getMethod().hasName(["getCanonicalPath", "getCanonicalFile"]) and
      this.asExpr() = [mc, mc.getQualifier()]
    )
    or
    // java.nio.file.Path.normalize / toAbsolutePath.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
      mc.getMethod().hasName(["normalize", "toAbsolutePath", "toRealPath"]) and
      this.asExpr() = [mc, mc.getQualifier()]
    )
    or
    // String.startsWith / Path.startsWith comparison against an
    // attachment-root prefix.
    exists(MethodCall mc |
      mc.getMethod().hasName("startsWith") and
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName(["java.lang", "java.nio.file"], ["String", "Path"]) and
      this.asExpr() = mc.getQualifier()
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
