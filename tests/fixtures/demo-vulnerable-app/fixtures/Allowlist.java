// Synthetic ground-truth fixture for InvariantCheck library v3.
// Not based on any real product code.
//
// Shared "good" allowlist barrier referenced by INV-01 / INV-11 clean
// controls. The CodeQL queries recognize the method names below as
// taint barriers via the source/sink/barrier class definitions.
package com.example.fixtures;

public final class Allowlist {

    private Allowlist() {}

    public static boolean isAllowedUrl(String url) {
        return url != null && url.startsWith("https://allowed.example.com/");
    }

    public static boolean isAllowedHost(String host) {
        return "allowed.example.com".equals(host);
    }

    public static boolean isAllowedDeeplink(String url) {
        return url != null && url.startsWith("signal://");
    }

    public static String validateDeeplinkTarget(String url) {
        if (isAllowedDeeplink(url)) {
            return url;
        }
        return null;
    }
}
