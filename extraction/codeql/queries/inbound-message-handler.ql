/**
 * @id aegisgraph/inbound-message-handler
 * @name AegisGraph: Methods that handle inbound message bodies/attachments
 * @description Methods whose parameters originate from a network-deserialized
 *              message body or attachment (Signal `IncomingMessage`,
 *              `IncomingMediaMessage`, MatrixRustSDK `EventTimelineItem`,
 *              `MessageContent`, etc.) and that proceed to dispatch handlers
 *              or persist content. Each result becomes an AegisGraph handler
 *              node.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external-input
 *       aegisgraph-sma
 */

import java

/**
 * Heuristic class set: messenger-specific inbound message wrappers. We use a
 * name-based match (rather than dataflow) because a Tier 3 extraction wants a
 * complete *handler surface* per query — even handlers whose individual
 * dataflow can't be proven here are valid AegisGraph nodes (they get
 * `claim_state="validation_tasked"` rather than "anchored" downstream).
 */
class InboundMessageType extends RefType {
  InboundMessageType() {
    this.getName().regexpMatch(
      "(?i).*(IncomingMessage|IncomingMediaMessage|IncomingTextMessage|IncomingGroupMessage|" +
        "MessageContent|Decrypted.*Message|EventTimelineItem|TimelineItemContent|" +
        "Envelope|SignalServiceContent|SignalServiceEnvelope).*"
    )
  }
}

class HandleMethod extends Method {
  HandleMethod() {
    // Method takes an InboundMessageType in its parameter list, and is named
    // like a handler ("handle*", "process*", "on*Message", "deliver*",
    // "dispatch*", "store*").
    exists(Parameter p |
      p.getCallable() = this and
      p.getType() instanceof InboundMessageType
    ) and
    this.getName().regexpMatch(
      "(?i)(handle|process|on|deliver|dispatch|store|persist|consume|insert|save).*"
    )
  }
}

from HandleMethod m, Parameter p
where p.getCallable() = m and p.getType() instanceof InboundMessageType
select m,
  "Inbound-message handler '" + m.getQualifiedName() +
    "' takes message type '" + p.getType().getName() +
    "' as parameter " + p.getPosition().toString() + "."
