// Synthetic ground-truth fixture for InvariantCheck INV-14.
// Not based on any real product code.
//
// Expected violations: 2
//   * writeBackupUnsigned: BackupSerializer.serialize() flows to
//     File output without MAC/signature wrap.
//   * readBackupUnverified: BackupReader.readBackup() blob flows into
//     BackupRestorer.restore() without verifying a MAC.
//
// Clean control: writeBackupSigned wraps in HmacSha256 MAC barrier.
package com.example.demo;

import java.io.File;
import java.io.FileOutputStream;
import com.example.fixtures.PolicyChecker;

public class BackupBlobUnauth {

    public void writeBackupUnsigned(BackupSerializer serializer, File out) throws Exception {
        // VIOLATION 1: serialized backup written without MAC/signature wrap.
        byte[] blob = serializer.serialize();
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(blob);
        }
    }

    public void readBackupUnverified(File in, BackupRestorer restorer) throws Exception {
        // VIOLATION 2: backup blob consumed without MAC verification.
        byte[] blob = BackupReader.readBackup(in);
        restorer.restore(blob);
    }

    // Clean control: MAC verification barrier present.
    public void writeBackupSigned(BackupSerializer serializer, File out, byte[] macKey) throws Exception {
        byte[] blob = serializer.serialize();
        byte[] mac = computeHmacSha256(blob, macKey);
        if (!PolicyChecker.verifyBackupMac(blob, mac)) {
            return;
        }
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(mac);
            fos.write(blob);
        }
    }

    private byte[] computeHmacSha256(byte[] blob, byte[] key) { return new byte[32]; }

    public static class BackupSerializer { public byte[] serialize() { return new byte[0]; } }
    public static class BackupReader { public static byte[] readBackup(File in) { return new byte[0]; } }
    public static class BackupRestorer { public void restore(byte[] blob) {} }
}
