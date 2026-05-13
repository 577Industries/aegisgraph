/**
 * @id aegisgraph/inv-11-deeplink-open-redirect
 * @name InvariantCheck INV-11: Deep-link open-redirect (STUB — M3.4 deliverable)
 * @description Deep-link handlers must not invoke startActivity /
 *              Custom Tabs / WebView.loadUrl with a URL parsed from an
 *              inbound intent unless the URL has passed through a host
 *              or scheme allowlist. This is the messenger-app open-
 *              redirect class: attacker-crafted deep links cause the
 *              app to load arbitrary URLs, enabling phishing, OAuth
 *              hijack, and SSRF amplification (combines with INV-01).
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id-mapping INV-11
 * @tags security
 *       external-input
 *       aegisgraph-invariantcheck
 *       mastg-platform-3
 *       ssdf-pw-5-1
 *       stub
 */

/*
 * ─────────────────────────────────────────────────────────────────────
 * STUB QUERY — NOT YET FULLY ENCODED (M3.4 deliverable)
 * ─────────────────────────────────────────────────────────────────────
 *
 * This file is committed so the M3.3 manifest entry for INV-11 resolves
 * to a real file on disk. The full encoding is scheduled for M3.4.
 *
 * Intended encoding sketch (do not delete — drives the M3.4 work):
 *
 *   Sources:
 *     - android.content.Intent.getData()
 *     - android.content.Intent.getDataString()
 *     - android.net.Uri.parse(...) called on a value extracted from an
 *       inbound Intent extra (DEEP_LINK, LINK, URL extras)
 *
 *   Sinks:
 *     - android.content.Context.startActivity(intent) where the intent's
 *       data is taint-flow-reachable from the source
 *     - androidx.browser.customtabs.CustomTabsIntent.launchUrl(context,
 *       uri) — second argument
 *     - android.webkit.WebView.loadUrl(url) — first argument
 *     - WebView.loadDataWithBaseURL — first and second arguments
 *
 *   Barriers (allowlist checks):
 *     - Methods named ["isAllowedDeeplink", "isAllowedHost",
 *       "checkSchemeAllowlist", "validateDeeplinkTarget",
 *       "isInternalScheme"]
 *     - String.startsWith / String.equals against a known-trusted-scheme
 *       constant (e.g. "signal://", "element://", "matrix:")
 *
 *   Configuration:
 *     class DeeplinkOpenRedirectConfig extends TaintTracking::Configuration
 *
 *   Select clause emits: sink, "INV-11: Deep-link URL from $@ reaches
 *     outbound load without scheme/host allowlist barrier."
 *
 * Until this stub is fleshed out, the runner produces an empty SARIF
 * result set for INV-11. The manifest entry truthfully records
 * `expected_violations: "unknown"` for all real targets and the demo
 * fixture; ground-truth assertion lands with the full encoding.
 *
 * See aegisgraph/invariants/manifest.json :: INV-11 for the canonical
 * statement, rationale, and MASTG / SSDF mapping.
 * ─────────────────────────────────────────────────────────────────────
 */

import java

// Trivially-empty query so codeql syntactically accepts the file while
// the stub is in place. select clause produces no results.
from Method m
where none()
select m, "INV-11 stub — see comment block in this file for the M3.4 encoding plan."
