/**
 * @id aegisgraph/inv-15-metadata-leak-outside-envelope
 * @name InvariantCheck INV-15: Message metadata escapes the encrypted envelope (STUB — M7 deliverable)
 * @description Message metadata (recipient list, timestamps, group IDs,
 *              thread IDs, read-receipts) must not escape the encrypted
 *              envelope on a network-egress path; metadata-bearing fields
 *              must be encrypted with the message body or routed through
 *              a sealed-sender / sealed-metadata channel. Plaintext
 *              metadata leakage reveals social graphs and timing patterns
 *              to network observers and server operators.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id-mapping INV-15
 * @tags security
 *       privacy
 *       network
 *       aegisgraph-invariantcheck
 *       mastg-network-1
 *       ssdf-pw-5-1
 *       stub
 */

/*
 * ─────────────────────────────────────────────────────────────────────
 * STUB QUERY — NOT YET FULLY ENCODED (M7 deliverable)
 * ─────────────────────────────────────────────────────────────────────
 *
 * This file is committed so the M5.3 manifest entry for INV-15 resolves
 * to a real file on disk. The full encoding is scheduled for M7.
 *
 * Intended encoding sketch (drives the M7 work):
 *
 *   This invariant is intrinsically heuristic — the line between
 *   "metadata that must be enveloped" and "metadata the server needs
 *   for routing" is target-specific. The encoding therefore models a
 *   conservative shape (metadata-getter → network-emit without
 *   envelope-wrap), and we accept low precision in exchange for
 *   completeness on the most blatant cases.
 *
 *   Sources (metadata-bearing field accessors):
 *     - Message.getRecipientList / Message.getRecipientIds
 *     - Message.getTimestamp / Message.getServerTimestamp
 *     - Message.getGroupId / Message.getThreadId
 *     - ReadReceipt.getReceiver / ReadReceipt.getMessageId
 *     - TypingIndicator.getRecipient
 *     - Methods on a *MessageMetadata / *Envelope*Metadata type returning
 *       any of {recipient_id, group_id, timestamp, thread_id,
 *       read_receipt_id}.
 *
 *   Sinks (network-egress emission points):
 *     - okhttp3.Request.Builder.url / .post / .put — the body argument.
 *     - okhttp3.WebSocket.send
 *     - io.ktor.client.HttpClient.request body
 *     - Retrofit @POST / @PUT method calls
 *     - WebSocket / WebRtcDataChannel.send
 *
 *   Barriers (envelope-wrap functions):
 *     - Methods named ["wrapInEnvelope", "encryptEnvelope",
 *       "sealMetadata", "sealedSenderEncrypt",
 *       "sealedMetadataEncrypt", "encryptWithSessionKey",
 *       "buildSealedSenderEnvelope"]
 *     - Calls on SealedSender / SealedSenderV2 / SealedMetadata classes.
 *     - org.signal.libsignal.metadata.SealedSessionCipher.encrypt
 *
 *   Configuration:
 *     class MetadataLeakConfig extends TaintTracking::Configuration { ... }
 *     module MetadataLeakFlow = TaintTracking::Global<MetadataLeakConfig>;
 *
 *   Select clause emits: sink, "INV-15: Metadata field from $@ reaches
 *     network egress without traversing a sealed-sender / envelope-wrap
 *     barrier."
 *
 *   Ground truth (planned):
 *     - demo-vulnerable-app: 2 violations (recipient_id and timestamp
 *       transmitted unsealed).
 *     - Signal Android: expected zero (sealed sender is implemented;
 *       a violation here would be a finding).
 *     - Element X: expected nonzero (Matrix protocol exposes some
 *       routing metadata by design; INV-15 reports the surface for
 *       evaluation, not necessarily as a defect).
 *
 * Until this stub is fleshed out, the runner produces an empty SARIF
 * result set for INV-15.
 *
 * See aegisgraph/invariants/manifest.json :: INV-15 for the canonical
 * statement, rationale, MASTG-NETWORK-1 / SSDF PW.5.1 mappings.
 *
 * TODO[M7]: Fully encode this query per the spec above. Coordinate the
 * Element X ground truth with the Matrix protocol team — some metadata
 * leakage is intentional and is documented in the Matrix spec; INV-15
 * should distinguish "leaks outside envelope but inside spec" from
 * "leaks outside envelope and outside spec." This may require a
 * per-target allowlist of acceptable metadata fields.
 * ─────────────────────────────────────────────────────────────────────
 */

import java

// Trivially-empty query so codeql syntactically accepts the file while
// the stub is in place. select clause produces no results.
from Method m
where none()
select m, "INV-15 stub — see comment block in this file for the M7 encoding plan."
