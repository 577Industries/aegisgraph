// Synthetic ground-truth fixture for InvariantCheck INV-15.
// Not based on any real product code.
//
// Expected violations: 2
//   * sendRecipientIdInClearMetadata: recipientId leaks via OkHttp Request
//     body outside the encrypted envelope.
//   * sendTimestampInQueryString: messageTimestamp leaks via URL query
//     parameter without envelope encryption.
//
// Clean control: sendSealed routes metadata through the SealedSender wrapper.
package com.example.demo

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.MediaType

class MetadataLeakOutsideEnvelope {

    fun sendRecipientIdInClearMetadata(recipientId: String, body: ByteArray, client: OkHttpClient) {
        // VIOLATION 1: recipientId placed in request body without sealed-sender wrapping.
        val json = """{"to":"$recipientId","payload":"${body.contentToString()}"}"""
        val req = Request.Builder()
            .url("https://relay.example.com/send")
            .post(RequestBody.create(MediaType.parse("application/json"), json))
            .build()
        client.newCall(req).execute()
    }

    fun sendTimestampInQueryString(ts: Long, body: ByteArray, client: OkHttpClient) {
        // VIOLATION 2: timestamp metadata leaks via URL query string.
        val req = Request.Builder()
            .url("https://relay.example.com/send?ts=$ts")
            .post(RequestBody.create(MediaType.parse("application/octet-stream"), body))
            .build()
        client.newCall(req).execute()
    }

    // Clean control: sealed-sender barrier wraps metadata into the envelope.
    fun sendSealed(recipientId: String, body: ByteArray, sealer: SealedSender, client: OkHttpClient) {
        val sealed = sealer.wrap(recipientId, body)
        val req = Request.Builder()
            .url("https://relay.example.com/send")
            .post(RequestBody.create(MediaType.parse("application/octet-stream"), sealed))
            .build()
        client.newCall(req).execute()
    }

    class SealedSender { fun wrap(to: String, body: ByteArray): ByteArray = body }
}
