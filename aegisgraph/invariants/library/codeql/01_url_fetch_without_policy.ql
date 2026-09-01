/**
 * @id aegisgraph/inv-01-url-fetch-without-policy
 * @name InvariantCheck INV-01: URL fetch without policy barrier
 * @description Attacker-controlled URL strings (link preview text,
 *              deep-link URI, push payload URL, QR-encoded URL,
 *              attachment fetch URL, federation room alias) reaching an
 *              outbound network call (OkHttp newCall, HttpURLConnection,
 *              Ktor, Retrofit) without passing through a URL allowlist
 *              or redirect-policy checker. This is the SSRF / internal-
 *              network probing / private-IP-exfiltration class.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id-mapping INV-01
 * @tags security
 *       external-input
 *       network
 *       aegisgraph-invariantcheck
 *       mastg-network-2
 *       ssdf-pw-5-1
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import UrlFetchPolicyFlow::PathGraph

/**
 * Sources: attacker-controllable URL-bearing strings.
 *
 * We model the messenger-specific shapes:
 *   * link-preview text/HTML scraped from incoming messages;
 *   * deep-link URIs delivered via android.net.Uri / Intent.getData;
 *   * push payload URL strings (notification body, FCM data field);
 *   * QR-encoded strings decoded by ML Kit / ZXing into String;
 *   * attachment fetch URLs included in inbound message envelopes;
 *   * federation room aliases / matrix.to URLs.
 */
class AttackerUrlSource extends DataFlow::Node {
  AttackerUrlSource() {
    // Plain Android user-input methods used by deep-link handlers and
    // notification payload deserializers.
    exists(MethodCall mc |
      mc.getMethod().hasName(["getText", "getDataString", "getUri", "getData"]) and
      this.asExpr() = mc
    )
    or
    // Inbound JSON / protobuf string-getters seen in messenger envelopes.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "getBody", "getUrl", "getPreviewUrl", "getAttachmentUrl",
            "getAvatarUrl", "getThumbnailUrl", "getCanonicalAlias"
          ]) and
      this.asExpr() = mc
    )
    or
    // Standard CodeQL remote-flow sources (HTTP, deserialization) so we
    // catch shapes the messenger-specific heuristics miss.
    this instanceof RemoteFlowSource
  }
}

/**
 * Sinks: outbound HTTP fetches.
 */
class NetworkFetchSink extends DataFlow::Node {
  NetworkFetchSink() {
    // OkHttp: client.newCall(Request) where the Request was built with a URL.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("okhttp3", "OkHttpClient") and
      mc.getMethod().hasName("newCall") and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // okhttp3.Request.Builder.url(String|HttpUrl|URL) — sink BEFORE the
    // request is dispatched, because the URL is set here.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("okhttp3", "Request$Builder") and
      mc.getMethod().hasName("url") and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // java.net.URL.openStream / openConnection.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.net", "URL") and
      mc.getMethod().hasName(["openStream", "openConnection"]) and
      this.asExpr() = mc.getQualifier()
    )
    or
    // HttpURLConnection.connect — qualifier is the URL-derived object.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("java.net", "HttpURLConnection") and
      mc.getMethod().hasName("connect") and
      this.asExpr() = mc.getQualifier()
    )
    or
    // Ktor io.ktor.client.HttpClient.request — argument is URL string.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("io.ktor.client", "HttpClient") and
      mc.getMethod().hasName(["request", "get", "post"]) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

/**
 * Sanitizers / policy barriers.
 *
 * We recognize:
 *   * URL-allowlist methods (isAllowedHost, isAllowedUrl,
 *     checkUrlAgainstAllowlist, validateScheme);
 *   * redirect-policy enforcement (checkRedirectPolicy,
 *     followsRedirectPolicy);
 *   * SafeBrowsing-style classifiers (isSafeUrl).
 *
 * When a value passes through any of these, taint is cleared.
 */
class PolicyCheckerBarrier extends DataFlow::Node {
  PolicyCheckerBarrier() {
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "isAllowedHost", "isAllowedUrl", "checkUrlAgainstAllowlist",
            "validateScheme", "checkRedirectPolicy", "followsRedirectPolicy",
            "isSafeUrl", "verifyUrlPolicy", "enforceUrlPolicy"
          ]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // Methods on a *Policy class that take a URL — treat the URL as
    // policy-checked once passed in.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().getName().regexpMatch(".*UrlPolicy|.*UrlAllowlist|.*FetchPolicy") and
      this.asExpr() = mc.getAnArgument()
    )
  }
}

/**
 * Configuration: taint flow from attacker URL sources to outbound HTTP
 * fetch sinks, with policy-checker barriers as sanitizers.
 */
module UrlFetchPolicyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof AttackerUrlSource }

  predicate isSink(DataFlow::Node snk) { snk instanceof NetworkFetchSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof PolicyCheckerBarrier }
}

module UrlFetchPolicyFlow = TaintTracking::Global<UrlFetchPolicyConfig>;

from UrlFetchPolicyFlow::PathNode source, UrlFetchPolicyFlow::PathNode sink
where UrlFetchPolicyFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-01: Attacker-controlled URL from $@ reaches network fetch without traversing a policy barrier.",
  source.getNode(), "this source"
