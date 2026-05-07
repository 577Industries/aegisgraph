/**
 * @id aegisgraph/link-preview-fetch
 * @name AegisGraph: Functions that take a URL parameter and fetch+parse the response
 * @description Methods that accept a URL/Uri/HttpUrl parameter and call into
 *              an HTTP client (OkHttp/HttpURLConnection/URL.openStream) to
 *              retrieve and parse the response. These are link-preview
 *              parsers, OG card fetchers, sticker-pack importers, etc.
 *              Each result becomes an AegisGraph parser node with path_class
 *              "link_preview".
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external-input
 *       network
 *       aegisgraph-sma
 */

import java

class UrlLikeType extends RefType {
  UrlLikeType() {
    this.getQualifiedName() = "java.net.URL" or
    this.getQualifiedName() = "java.net.URI" or
    this.getQualifiedName() = "android.net.Uri" or
    this.getQualifiedName() = "okhttp3.HttpUrl" or
    this.getQualifiedName() = "java.lang.String"
  }
}

class HttpFetchMethod extends Method {
  HttpFetchMethod() {
    // Common HTTP-client entry points used in real Android codebases.
    this.getQualifiedName() = "java.net.URL.openStream" or
    this.getQualifiedName() = "java.net.URL.openConnection" or
    this.getDeclaringType().getQualifiedName() = "okhttp3.OkHttpClient" or
    this.getDeclaringType().getQualifiedName() = "okhttp3.Call" or
    this.getDeclaringType().getQualifiedName() = "okhttp3.Request$Builder" or
    this.getDeclaringType().getQualifiedName() = "java.net.HttpURLConnection"
  }
}

class FetchAndParseMethod extends Method {
  FetchAndParseMethod() {
    // Has a URL-like parameter (signal that the URL came from outside).
    exists(Parameter p |
      p.getCallable() = this and p.getType() instanceof UrlLikeType
    ) and
    // And reaches an HTTP fetch call inside its body.
    exists(MethodCall mc |
      mc.getEnclosingCallable() = this and
      mc.getMethod() instanceof HttpFetchMethod
    )
  }
}

from FetchAndParseMethod m, Parameter p
where p.getCallable() = m and p.getType() instanceof UrlLikeType
select m,
  "Link-preview-style fetch+parse method '" + m.getQualifiedName() +
    "' takes URL parameter and reaches an HTTP fetch call."
