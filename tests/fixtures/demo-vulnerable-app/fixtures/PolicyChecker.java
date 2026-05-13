// Synthetic ground-truth fixture for InvariantCheck library v3.
// Not based on any real product code.
//
// Shared "good" policy checker referenced by misc clean controls.
package com.example.fixtures;

public final class PolicyChecker {

    private PolicyChecker() {}

    public static boolean checkRedirectPolicy(String url) {
        return url != null && url.startsWith("https://");
    }

    public static boolean isPathSafe(String path) {
        return path != null && !path.contains("..") && !path.startsWith("/");
    }

    public static String sanitizeAttachmentName(String name) {
        if (name == null) return null;
        return name.replace("..", "_").replace("/", "_");
    }

    public static boolean verifyBackupMac(byte[] blob, byte[] mac) {
        return blob != null && mac != null && mac.length == 32;
    }
}
