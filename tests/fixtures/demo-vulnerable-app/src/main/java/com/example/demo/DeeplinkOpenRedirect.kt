// Synthetic ground-truth fixture for InvariantCheck INV-11.
// Not based on any real product code.
//
// Expected violations: 3
//   * openDeeplinkStartActivity: Intent.getData() flows into
//     Context.startActivity(Intent.setData) without allowlist.
//   * openDeeplinkCustomTab: Intent.getDataString() flows into
//     CustomTabsIntent.launchUrl without allowlist.
//   * openDeeplinkWebview: Intent.getStringExtra("DEEP_LINK") flows
//     into WebView.loadUrl without allowlist.
//
// Clean control: openDeeplinkSafe uses Allowlist.isAllowedDeeplink barrier.
package com.example.demo

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.webkit.WebView
import androidx.browser.customtabs.CustomTabsIntent
import com.example.fixtures.Allowlist

class DeeplinkOpenRedirect {

    fun openDeeplinkStartActivity(context: Context, inbound: Intent) {
        // VIOLATION 1: inbound.getData() flows to startActivity without allowlist.
        val targetUri: Uri? = inbound.data
        val outbound = Intent(Intent.ACTION_VIEW)
        outbound.setData(targetUri)
        context.startActivity(outbound)
    }

    fun openDeeplinkCustomTab(context: Context, inbound: Intent, tabs: CustomTabsIntent) {
        // VIOLATION 2: getDataString() flows to CustomTabsIntent.launchUrl without allowlist.
        val urlStr: String? = inbound.dataString
        val uri = Uri.parse(urlStr)
        tabs.launchUrl(context, uri)
    }

    fun openDeeplinkWebview(inbound: Intent, webView: WebView) {
        // VIOLATION 3: getStringExtra("DEEP_LINK") flows to WebView.loadUrl.
        val url: String? = inbound.getStringExtra("DEEP_LINK")
        webView.loadUrl(url ?: "")
    }

    // Clean control: allowlist barrier present.
    fun openDeeplinkSafe(context: Context, inbound: Intent) {
        val urlStr: String? = inbound.dataString
        if (urlStr == null || !Allowlist.isAllowedDeeplink(urlStr)) {
            return
        }
        val outbound = Intent(Intent.ACTION_VIEW)
        outbound.setData(Uri.parse(urlStr))
        context.startActivity(outbound)
    }
}
