// Synthetic ground-truth fixture for InvariantCheck INV-15.
// Not based on any real product code.
//
// Expected violations: 2
//   * sendRecipientIdInClearMetadata: OutgoingMessage.recipientId leaks via
//     the OkHttp request body outside the encrypted envelope.
//   * sendTimestampInQueryString: OutgoingMessage.timestamp leaks via a URL
//     query parameter without envelope encryption.
//
// Clean control: sendSealed routes metadata through the SealedSender wrapper.
package com.example.demo

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.MediaType

class MetadataLeakOutsideEnvelope {

    fun sendRecipientIdInClearMetadata(msg: OutgoingMessage, client: OkHttpClient) {
        // VIOLATION 1: recipient id placed in the request body without sealed-sender wrapping.
        val json = """{"to":"${msg.recipientId}","payload":"${msg.body.contentToString()}"}"""
        val req = Request.Builder()
            .url("https://relay.example.com/send")
            .post(RequestBody.create(MediaType.parse("application/json"), json))
            .build()
        client.newCall(req).execute()
    }

    fun sendTimestampInQueryString(msg: OutgoingMessage, client: OkHttpClient) {
        // VIOLATION 2: sent-timestamp metadata leaks via the URL query string.
        val req = Request.Builder()
            .url("https://relay.example.com/send?ts=${msg.timestamp}")
            .post(RequestBody.create(MediaType.parse("application/octet-stream"), msg.body))
            .build()
        client.newCall(req).execute()
    }

    // Clean control: sealed-sender barrier wraps metadata into the envelope.
    fun sendSealed(msg: OutgoingMessage, sealer: SealedSender, client: OkHttpClient) {
        val sealed = sealer.wrap(msg.recipientId, msg.body)
        val req = Request.Builder()
            .url("https://relay.example.com/send")
            .post(RequestBody.create(MediaType.parse("application/octet-stream"), sealed))
            .build()
        client.newCall(req).execute()
    }

    class OutgoingMessage {
        val recipientId: String = ""
        val timestamp: Long = 0L
        val body: ByteArray = ByteArray(0)
    }

    class SealedSender { fun wrap(to: String, body: ByteArray): ByteArray = body }
}
