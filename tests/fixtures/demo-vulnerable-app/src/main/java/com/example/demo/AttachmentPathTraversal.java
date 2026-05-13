// Synthetic ground-truth fixture for InvariantCheck INV-10.
// Not based on any real product code.
//
// Expected violations: 2
//   * writeAttachment: Attachment.getFileName() flows to new File()
//     without canonicalization.
//   * writeAttachmentNio: Attachment.getOriginalName() flows to
//     Files.write without normalization.
//
// Clean control: writeAttachmentSafe uses File.getCanonicalPath barrier.
package com.example.demo;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class AttachmentPathTraversal {

    public void writeAttachment(Attachment att, File root, byte[] data) throws Exception {
        // VIOLATION 1: filename flows to new File / FileOutputStream without canonicalization.
        String name = att.getFileName();
        File out = new File(root, name);
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(data);
        }
    }

    public void writeAttachmentNio(Attachment att, byte[] data) throws Exception {
        // VIOLATION 2: filename flows to Files.write via Paths.get without normalization.
        String name = att.getOriginalName();
        Path p = Paths.get("/var/attachments/" + name);
        Files.write(p, data);
    }

    // Clean control: canonicalization barrier present.
    public void writeAttachmentSafe(Attachment att, File root, byte[] data) throws Exception {
        String name = att.getFileName();
        File out = new File(root, name);
        String canonical = out.getCanonicalPath();
        if (!canonical.startsWith(root.getCanonicalPath() + File.separator)) {
            return;
        }
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(data);
        }
    }

    public static class Attachment {
        public String getFileName() { return ""; }
        public String getOriginalName() { return ""; }
    }
}
