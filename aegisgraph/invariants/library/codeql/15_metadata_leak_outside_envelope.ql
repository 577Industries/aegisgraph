/**
 * @id aegisgraph/inv-15-metadata-leak-outside-envelope
 * @name InvariantCheck INV-15: Message metadata escapes the encrypted envelope
 * @description Message metadata (recipient list, timestamps, group IDs,
 *              thread IDs, read-receipts) must not escape the encrypted
 *              envelope on a network-egress path; metadata-bearing fields
 *              must be encrypted with the message body or routed through
 *              a sealed-sender / sealed-metadata channel. Plaintext
 *              metadata leakage reveals social graphs and timing patterns
 *              to network observers and server operators, defeating the
 *              privacy goals of an SMA.
 *
 *              This invariant is intrinsically heuristic — the line
 *              between "metadata that must be enveloped" and "metadata
 *              the server needs for routing" is target-specific. The
 *              encoding favors completeness over precision: it reports
 *              any metadata-getter to network-egress flow that doesn't
 *              cross a sealed-sender / envelope-wrap barrier. The runner
 *              treats Element X findings here as observational (Matrix
 *              spec admits some metadata) while Signal findings are
 *              expected to be zero.
 * @kind path-problem
 * @problem.severity warning
 * @precision low
 * @id-mapping INV-15
 * @tags security
 *       privacy
 *       network
 *       aegisgraph-invariantcheck
 *       mastg-network-1
 *       ssdf-pw-5-1
 */

/*
 * Encoding notes:
 *
 *   Sources: metadata field accessors on a Message / Envelope / ReadReceipt
 *            / TypingIndicator object — recipient_id, group_id,
 *            timestamp, thread_id, read_receipt_id.
 *
 *   Sinks: network-egress emission points — okhttp3.Request.Builder,
 *          OkHttpClient.newCall, HttpURLConnection.connect,
 *          io.ktor.client.HttpClient.request, WebSocket.send,
 *          RetrofitService methods annotated @POST/@PUT.
 *
 *   Barriers: envelope-wrap and sealed-sender helpers — wrapInEnvelope,
 *             encryptEnvelope, sealMetadata, sealedSenderEncrypt,
 *             SealedSessionCipher.encrypt, SealedSenderV2 helpers.
 *
 * TODO[ground-truth-pass]: Signal-android org.signal.libsignal.metadata
 * .SealedSessionCipher and Element-X equivalent class names are
 * placeholders rooted in public library naming; the M7-GT pass pins
 * them against the anchored commits.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import MetadataLeakFlow::PathGraph

/**
 * Sources: metadata-bearing field accessors.
 */
class MessageMetadataSource extends DataFlow::Node {
  MessageMetadataSource() {
    // Recipient / addressing fields.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "getRecipient", "getRecipientList", "getRecipientId",
            "getRecipientIds", "getTo", "getDestination",
            "getReceiver", "getReceiverId", "getReceiverList"
          ]) and
      this.asExpr() = mc
    )
    or
    // Time and identifier metadata.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "getTimestamp", "getServerTimestamp", "getSentTimestamp",
            "getGroupId", "getRoomId", "getThreadId", "getConversationId",
            "getMessageId", "getEventId"
          ]) and
      this.asExpr() = mc
    )
    or
    // Receipt / indicator metadata.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "getReadReceipt", "getReadReceiptList",
            "getDeliveryReceipt", "getTypingIndicator",
            "getReadAt", "getReadStatus"
          ]) and
      this.asExpr() = mc
    )
    or
    // Top-of-handler parameters typed *MessageMetadata / *EnvelopeMetadata
    // / *MessageContext.
    exists(Parameter p |
      p.getType()
          .(RefType)
          .getName()
          .regexpMatch(".*MessageMetadata.*|.*EnvelopeMetadata.*|.*MessageContext.*|.*ReadReceiptList.*") and
      this.asExpr() = p.getAnAccess()
    )
  }
}

/**
 * Sinks: network-egress emission points.
 */
class NetworkEgressSink extends DataFlow::Node {
  NetworkEgressSink() {
    // OkHttp Request.Builder.body / .post / .put — the body argument.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("okhttp3", "Request$Builder") and
      mc.getMethod()
          .hasName(["post", "put", "patch", "delete", "method"]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // OkHttpClient.newCall — the Request argument.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("okhttp3", "OkHttpClient") and
      mc.getMethod().hasName("newCall") and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // HttpURLConnection write paths.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("java.net", "HttpURLConnection") and
      mc.getMethod().hasName(["connect", "getOutputStream"]) and
      this.asExpr() = [mc, mc.getQualifier()]
    )
    or
    // Ktor io.ktor.client.HttpClient.request / .post / .put.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("io.ktor.client", "HttpClient") and
      mc.getMethod()
          .hasName(["request", "post", "put", "patch", "delete", "submitForm"]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // WebSocket / okhttp3.WebSocket.send.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName(["okhttp3", "java.net"], ["WebSocket", "URI"]) and
      mc.getMethod().hasName("send") and
      this.asExpr() = mc.getArgument(0)
    )
    or
    // WebRTC DataChannel.send.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*DataChannel.*") and
      mc.getMethod().hasName("send") and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

/**
 * Barriers: envelope-wrap and sealed-sender helpers.
 */
class EnvelopeWrapBarrier extends DataFlow::Node {
  EnvelopeWrapBarrier() {
    // Named envelope / sealed helpers.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "wrapInEnvelope", "encryptEnvelope", "sealMetadata",
            "sealedSenderEncrypt", "sealedMetadataEncrypt",
            "encryptWithSessionKey", "buildSealedSenderEnvelope",
            "encryptEnvelopeContents", "sealEnvelope",
            "encryptForRecipient", "sealMessage"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // Calls on SealedSender / SealedSenderV2 / SealedMetadata / Sealed*
    // classes — the sealed cipher itself.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*SealedSender.*|.*SealedSenderV2.*|.*SealedMetadata.*|.*SealedSessionCipher.*|.*Envelope$|.*EnvelopeBuilder.*") and
      mc.getMethod()
          .hasName(["encrypt", "build", "seal", "wrap", "create"]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // libsignal-style SealedSessionCipher.encrypt.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("org.signal.libsignal.metadata", "SealedSessionCipher") and
      mc.getMethod().hasName("encrypt") and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
  }
}

/**
 * Configuration: taint flow from message-metadata sources to network-
 * egress sinks, with envelope-wrap helpers as barriers.
 */
module MetadataLeakConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof MessageMetadataSource }

  predicate isSink(DataFlow::Node snk) { snk instanceof NetworkEgressSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof EnvelopeWrapBarrier }
}

module MetadataLeakFlow = TaintTracking::Global<MetadataLeakConfig>;

from MetadataLeakFlow::PathNode source, MetadataLeakFlow::PathNode sink
where MetadataLeakFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-15: Message metadata from $@ reaches network-egress sink without traversing a sealed-sender or envelope-wrap barrier.",
  source.getNode(), "this source"
