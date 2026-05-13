/**
 * @id aegisgraph/inv-11-deeplink-open-redirect
 * @name InvariantCheck INV-11: Deep-link open-redirect
 * @description Deep-link handlers must not invoke startActivity /
 *              Custom Tabs / WebView.loadUrl with a URL parsed from an
 *              inbound intent (Intent.getData, Intent.getDataString, or
 *              Uri.parse of an intent extra) unless the URL has passed
 *              through a host / scheme allowlist or startsWith-prefix
 *              comparison against trusted-scheme constants. This is the
 *              messenger-app open-redirect class: attacker-crafted deep
 *              links cause the app to load arbitrary URLs, enabling
 *              phishing, OAuth-flow hijack, and SSRF amplification
 *              (combines with INV-01).
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id-mapping INV-11
 * @tags security
 *       external-input
 *       aegisgraph-invariantcheck
 *       mastg-platform-3
 *       ssdf-pw-5-1
 */

/*
 * Encoding notes:
 *
 *   Sources: deep-link URL-bearing values obtained from an inbound
 *            Intent — getData() / getDataString() / Uri.parse on an
 *            extra with a "DEEP_LINK" / "LINK" / "URL" key.
 *
 *   Sinks: outbound URL loads — Context.startActivity (when the
 *          inner intent's data is taint-reachable),
 *          CustomTabsIntent.launchUrl arg(1), WebView.loadUrl arg(0),
 *          WebView.loadDataWithBaseURL arg(0) / arg(1).
 *
 *   Barriers: allowlist helpers (isAllowedDeeplink, isAllowedHost,
 *             checkSchemeAllowlist, validateDeeplinkTarget,
 *             isInternalScheme) and String.startsWith / String.equals
 *             against a known trusted-scheme constant.
 *
 * TODO[ground-truth-pass]: confirm Signal-android DeeplinkActivity and
 * Element-X PermalinkParser class names against the pinned commits;
 * the queries below are structural and rely on Android-framework
 * standard APIs only.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

/**
 * Sources: attacker-controllable URLs sourced from an inbound Intent.
 *
 * Three shapes:
 *   * Intent.getData() / Intent.getDataString() — the standard deep-link
 *     entry point on an Activity.
 *   * Intent.getStringExtra(name) where the extra name matches a
 *     deep-link convention (DEEP_LINK, LINK, URL, deeplink, target_url).
 *   * Uri.parse on a value derived from an Intent extra getter.
 */
class DeeplinkUrlSource extends DataFlow::Node {
  DeeplinkUrlSource() {
    // Intent.getData() / Intent.getDataString() — the standard deep-link
    // entry point on an Activity.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("android.content", "Intent") and
      mc.getMethod().hasName(["getData", "getDataString"]) and
      this.asExpr() = mc
    )
    or
    // Intent.getStringExtra / getParcelableExtra where the extra name is
    // a deep-link key.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("android.content", "Intent") and
      mc.getMethod()
          .hasName(["getStringExtra", "getCharSequenceExtra", "getParcelableExtra"]) and
      mc.getArgument(0).(StringLiteral).getValue().regexpMatch("(?i).*(deep[_-]?link|^link$|^url$|target[_-]?url|redirect[_-]?url).*") and
      this.asExpr() = mc
    )
    or
    // Uri.parse called with a value derived from an Intent (heuristic
    // structural match — the result of Uri.parse is treated as a source
    // when the argument is itself attacker-controlled).
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("android.net", "Uri") and
      mc.getMethod().hasName("parse") and
      this.asExpr() = mc
    )
  }
}

/**
 * Sinks: outbound URL loads that consume the attacker-controlled URL.
 */
class OutboundLoadSink extends DataFlow::Node {
  OutboundLoadSink() {
    // android.content.Context.startActivity(Intent) — the Intent is the
    // sink expression; downstream taint-flow from getData() / setData()
    // chains into the started Intent's data slot is captured by
    // CodeQL's Intent-to-Intent flow.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("android.content", "Context") and
      mc.getMethod().hasName(["startActivity", "startActivityForResult"]) and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // Intent.setData(Uri) — the Uri is the sink; the resulting Intent
    // is then passed to startActivity.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("android.content", "Intent") and
      mc.getMethod().hasName(["setData", "setDataAndType"]) and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // androidx.browser.customtabs.CustomTabsIntent.launchUrl(context, uri)
    // — the Uri argument (arg index 1) is the sink.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("androidx.browser.customtabs", "CustomTabsIntent") and
      mc.getMethod().hasName("launchUrl") and
      this.asExpr() = mc.getArgument(1)
    )
    or
    // android.webkit.WebView.loadUrl(url) — arg 0.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebView") and
      mc.getMethod().hasName(["loadUrl", "postUrl"]) and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // android.webkit.WebView.loadDataWithBaseURL(baseUrl, data, ...) —
    // arg 0 and arg 1 are both sinks.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebView") and
      mc.getMethod().hasName("loadDataWithBaseURL") and
      this.asExpr() = [mc.getArgument(0), mc.getArgument(1)]
    )
  }
}

/**
 * Barriers: scheme / host allowlist checks and trusted-scheme prefix
 * comparisons.
 */
class AllowlistBarrier extends DataFlow::Node {
  AllowlistBarrier() {
    // Allowlist helper methods — name-based.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "isAllowedDeeplink", "isAllowedHost", "checkSchemeAllowlist",
            "validateDeeplinkTarget", "isInternalScheme",
            "verifyDeeplinkOrigin", "isTrustedDeeplink", "enforceSchemeAllowlist"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // String.startsWith / String.equals on a trusted-scheme prefix
    // constant. We treat any startsWith/equals call where the
    // *constant* argument matches a known trusted-scheme prefix as a
    // barrier.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      mc.getMethod().hasName(["startsWith", "equals", "equalsIgnoreCase"]) and
      mc.getArgument(0)
          .(StringLiteral)
          .getValue()
          .regexpMatch("(?i)^(https?:|signal:|element:|matrix:|sgnl:|app:|mxc:|internal:)(/{0,2}.*)?$") and
      this.asExpr() = mc.getQualifier()
    )
    or
    // Uri.getScheme() comparisons routed through name-based scheme
    // verifiers.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName(["isHttpsScheme", "isCustomScheme", "verifyScheme"]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
  }
}

/**
 * Configuration: taint flow from deep-link sources to outbound load
 * sinks, with allowlist / scheme-prefix barriers as sanitizers.
 */
module DeeplinkOpenRedirectConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof DeeplinkUrlSource }

  predicate isSink(DataFlow::Node snk) { snk instanceof OutboundLoadSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof AllowlistBarrier }
}

module DeeplinkOpenRedirectFlow = TaintTracking::Global<DeeplinkOpenRedirectConfig>;

from DeeplinkOpenRedirectFlow::PathNode source, DeeplinkOpenRedirectFlow::PathNode sink
where DeeplinkOpenRedirectFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-11: Deep-link URL from $@ reaches outbound load without allowlist barrier.",
  source.getNode(), "this source"
