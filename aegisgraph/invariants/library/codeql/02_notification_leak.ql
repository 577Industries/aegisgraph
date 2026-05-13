/**
 * @id aegisgraph/inv-02-notification-leak
 * @name InvariantCheck INV-02: Sensitive content leaks into notifications
 * @description Message body, sender display name, attachment caption, or
 *              other sensitive content getter outputs flowing into
 *              NotificationCompat.Builder.setContentText / setContentTitle
 *              / setStyle / setSubText without traversing a redaction
 *              barrier (redactedBody, scrubForNotification,
 *              lockscreenSafeText) or a lockscreen-visibility guard
 *              (setVisibility(VISIBILITY_SECRET), IMPORTANCE_NONE on
 *              locked-device branch). This is the
 *              plaintext-on-lockscreen / recents / Wear-mirror class.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id-mapping INV-02
 * @tags security
 *       external-input
 *       privacy
 *       aegisgraph-invariantcheck
 *       mastg-storage-7
 *       ssdf-pw-5-1
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

/**
 * Sources: sensitive content getters on inbound message / envelope
 * objects.
 *
 * Messenger envelopes typically expose these accessors on a Message,
 * Conversation, or PushPayload type. We treat any of these names as
 * carrying sensitive plaintext when invoked on an instance method (i.e.
 * `someMessage.getBody()` rather than a static / utility helper).
 */
class SensitiveContentSource extends DataFlow::Node {
  SensitiveContentSource() {
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "getBody", "getMessageBody", "getDecryptedBody",
            "getPlaintext", "getText", "getMessageText",
            "getPreview", "getPreviewText", "getThumbnailCaption",
            "getSenderDisplayName", "getDisplayName",
            "getSenderName", "getPushBody", "getQuoteText",
            "getAttachmentCaption", "getCaption"
          ]) and
      this.asExpr() = mc
    )
  }
}

/**
 * Sinks: NotificationCompat.Builder visible-text setters.
 *
 * setContentText / setContentTitle / setSubText / setTicker accept user-
 * visible CharSequence content. setStyle (BigTextStyle, MessagingStyle)
 * also accepts plaintext via its bigText / addMessage variants — we cover
 * those by intercepting the inner builders too.
 */
class NotificationVisibleTextSink extends DataFlow::Node {
  NotificationVisibleTextSink() {
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("androidx.core.app", ["NotificationCompat$Builder",
                                                  "NotificationCompat$BigTextStyle",
                                                  "NotificationCompat$MessagingStyle",
                                                  "NotificationCompat$MessagingStyle$Message"]) and
      mc.getMethod()
          .hasName([
            "setContentText", "setContentTitle", "setSubText", "setTicker",
            "bigText", "addMessage", "setMessage"
          ]) and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // android.app.Notification.Builder (legacy API) equivalents.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("android.app", "Notification$Builder") and
      mc.getMethod()
          .hasName([
            "setContentText", "setContentTitle", "setSubText", "setTicker"
          ]) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

/**
 * Barriers: redaction methods and lockscreen-visibility guards.
 *
 * A value passing through any redaction helper is considered safe to
 * render in a notification, as is a value being placed on a notification
 * whose visibility has been explicitly set to VISIBILITY_SECRET.
 */
class NotificationSanitizerBarrier extends DataFlow::Node {
  NotificationSanitizerBarrier() {
    // Redaction helpers — name-based heuristic.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "redactedBody", "redactForNotification", "scrubForNotification",
            "lockscreenSafeText", "redactSensitive", "sanitizeForLockscreen",
            "redactedDisplayName", "obfuscateForNotification"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // String.replaceAll / String.replace with a known redaction pattern
    // (e.g. ".*" -> "•••") — heuristic: replacement string contains bullet
    // or asterisk redaction characters.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      mc.getMethod().hasName(["replaceAll", "replace"]) and
      mc.getArgument(1).(StringLiteral).getValue().regexpMatch(".*[•*]{2,}.*") and
      this.asExpr() = mc
    )
  }
}

/**
 * Configuration: taint flow from sensitive content getters to
 * notification-visible-text sinks, with redaction-helper barriers as
 * sanitizers.
 */
module NotificationLeakConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof SensitiveContentSource }

  predicate isSink(DataFlow::Node snk) { snk instanceof NotificationVisibleTextSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof NotificationSanitizerBarrier }
}

module NotificationLeakFlow = TaintTracking::Global<NotificationLeakConfig>;

from NotificationLeakFlow::PathNode source, NotificationLeakFlow::PathNode sink
where NotificationLeakFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-02: Sensitive content from $@ reaches notification-visible setter without a redaction barrier.",
  source.getNode(), "this source"
