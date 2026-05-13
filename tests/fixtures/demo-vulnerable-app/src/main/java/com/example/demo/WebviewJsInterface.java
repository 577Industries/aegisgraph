// Synthetic ground-truth fixture for InvariantCheck INV-09.
// Not based on any real product code.
//
// Expected violations: 2
//   * bareBridge: WebView.addJavascriptInterface() called without
//     setAllowFileAccess(false) / setAllowContentAccess(false).
//   * jsEnabledThenBridge: setJavaScriptEnabled(true) followed by
//     addJavascriptInterface() without same-origin guard.
//
// Clean control: hardenedBridge sets file/content access to false AND
// checks isSameOrigin before adding the bridge.
package com.example.demo;

import android.webkit.WebView;
import android.webkit.WebSettings;

public class WebviewJsInterface {

    public void bareBridge(WebView webView, Object jsBridge) {
        // VIOLATION 1: bare addJavascriptInterface without hardening calls.
        webView.addJavascriptInterface(jsBridge, "AppBridge");
    }

    public void jsEnabledThenBridge(WebView webView, Object jsBridge) {
        // VIOLATION 2: setJavaScriptEnabled(true) followed by
        // addJavascriptInterface without same-origin guard.
        webView.getSettings().setJavaScriptEnabled(true);
        webView.addJavascriptInterface(jsBridge, "AppBridge");
    }

    // Clean control: hardening calls AND same-origin guard present.
    public void hardenedBridge(WebView webView, Object jsBridge, String origin) {
        WebSettings settings = webView.getSettings();
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        if (!isSameOrigin(origin)) {
            return;
        }
        webView.addJavascriptInterface(jsBridge, "AppBridge");
    }

    private boolean isSameOrigin(String origin) {
        return "https://allowed.example.com".equals(origin);
    }
}
