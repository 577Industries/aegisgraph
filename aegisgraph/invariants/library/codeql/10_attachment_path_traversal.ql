/**
 * @id aegisgraph/inv-10-attachment-path-traversal
 * @name InvariantCheck INV-10: Attachment filename path traversal (STUB — M7 deliverable)
 * @description Attachment filenames received from inbound messages must
 *              not flow into java.io.File.write / FileOutputStream
 *              constructor / Files.write without passing through a path-
 *              canonicalization barrier (File.getCanonicalPath, prefix
 *              comparison against the attachment-directory root). A
 *              filename containing `..`, an absolute path, or NUL bytes
 *              can escape the attachment directory and overwrite app
 *              private storage including key material.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id-mapping INV-10
 * @tags security
 *       external-input
 *       file-system
 *       aegisgraph-invariantcheck
 *       mastg-storage-2
 *       ssdf-pw-5-1
 *       stub
 */

/*
 * ─────────────────────────────────────────────────────────────────────
 * STUB QUERY — NOT YET FULLY ENCODED (M7 deliverable)
 * ─────────────────────────────────────────────────────────────────────
 *
 * This file is committed so the M5.3 manifest entry for INV-10 resolves
 * to a real file on disk. The full encoding is scheduled for M7.
 *
 * Intended encoding sketch (drives the M7 work):
 *
 *   Sources (attachment-name getters on inbound messages):
 *     - Attachment.getFileName / Attachment.getDisplayName /
 *       Attachment.getOriginalName / AttachmentPointer.getFileName
 *     - MediaItem.getFileName / DocumentMessage.getFileName
 *     - Top-of-handler parameters typed as a *Attachment / *MediaItem /
 *       *Document carrying an attacker-controlled name.
 *
 *   Sinks (file-write surfaces):
 *     - new java.io.File(parent, name) where `name` is the sink.
 *     - new java.io.FileOutputStream(file_or_path) constructor argument.
 *     - java.nio.file.Files.write(path, bytes) — first arg.
 *     - Path.resolve(name) on a base path — the resolve argument.
 *     - Okio: okio.Path.resolve(name) — similar.
 *
 *   Barriers (canonicalization / containment checks):
 *     - java.io.File.getCanonicalPath() followed by a startsWith /
 *       String.startsWith comparison against the attachment-root path.
 *     - Methods named ["isWithinAttachmentDir", "isPathSafe",
 *       "stripPathTraversal", "sanitizeAttachmentName",
 *       "ensureInsideRoot", "normalize"]
 *     - okio.Path.normalize() with subsequent startsWith.
 *     - Pattern-based filtering: Pattern.matches against a
 *       safe-filename-only regex.
 *
 *   Configuration:
 *     class AttachmentPathTraversalConfig extends
 *       TaintTracking::Configuration { ... }
 *     module AttachmentPathTraversalFlow =
 *       TaintTracking::Global<AttachmentPathTraversalConfig>;
 *
 *   Select clause emits: sink, "INV-10: Attachment filename from $@
 *     reaches file-write without a canonicalization or containment
 *     barrier."
 *
 *   Ground truth (planned):
 *     - demo-vulnerable-app: 2 violations (one direct File constructor,
 *       one via Path.resolve without normalization).
 *     - Signal Android / Element X: unknown.
 *
 * Until this stub is fleshed out, the runner produces an empty SARIF
 * result set for INV-10.
 *
 * See aegisgraph/invariants/manifest.json :: INV-10 for the canonical
 * statement, rationale, MASTG-STORAGE-2 / SSDF PW.5.1 mappings.
 *
 * TODO[M7]: Fully encode this query per the spec above. Note that
 * Android's ContentResolver / DocumentFile surface introduces an
 * additional path layer — make sure the encoding covers `Uri` values
 * extracted from inbound attachments as well as raw strings.
 * ─────────────────────────────────────────────────────────────────────
 */

import java

// Trivially-empty query so codeql syntactically accepts the file while
// the stub is in place. select clause produces no results.
from Method m
where none()
select m, "INV-10 stub — see comment block in this file for the M7 encoding plan."
