/**
 * @id aegisgraph/entry-point-intent
 * @name AegisGraph: Activities/Services/Receivers/Providers with intent filters accepting external schemes
 * @description Surfaces Android components declared with intent filters that
 *              accept externally-controllable schemes (http/https/content/file/
 *              custom). Each result becomes an AegisGraph entry_point node.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external-input
 *       android
 *       aegisgraph-sma
 */

import java
import semmle.code.java.frameworks.android.AndroidManifest
import semmle.code.java.frameworks.android.Intents

/**
 * A component (Activity/Service/BroadcastReceiver/ContentProvider) that has at
 * least one <intent-filter> child. We then check the filter's <data> tag for
 * a scheme that is reachable from outside the app.
 */
class ExportedComponent extends AndroidComponent {
  ExportedComponent() {
    exists(IntentFilter f | f.getEnclosingComponent() = this)
  }
}

predicate externallyReachableScheme(string scheme) {
  scheme = "http" or
  scheme = "https" or
  scheme = "content" or
  scheme = "file" or
  scheme = "geo" or
  scheme = "tel" or
  scheme = "mailto" or
  // Custom schemes (anything not matching the platform allow-list) are also
  // externally reachable; we capture the most common attack vectors above
  // explicitly and let any non-empty scheme on an exported component be a
  // candidate.
  scheme != ""
}

from ExportedComponent c, IntentFilter f, string scheme
where
  f.getEnclosingComponent() = c and
  scheme = f.getADataElement().getScheme() and
  externallyReachableScheme(scheme)
select c,
  "Exported Android component '" + c.getName() +
    "' accepts external scheme '" + scheme + "' via intent-filter."
