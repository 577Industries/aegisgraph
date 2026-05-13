// Synthetic ground-truth fixture for InvariantCheck INV-13.
// Not based on any real product code.
//
// Expected violations: 2
//   * provisionSessionFromQr: Barcode.getRawValue() flows into
//     SessionStore.storeSession without KEX-completion barrier.
//   * provisionIdentityFromQr: zxing Result.getText() flows into
//     IdentityKeyStore.saveIdentity without KEX-completion barrier.
//
// Clean control: provisionSafe uses NoiseHandshakeState.complete barrier.
package com.example.demo

import com.example.fixtures.KexCompletion.NoiseHandshakeState

class QrPayloadUnverified {

    fun provisionSessionFromQr(barcode: Barcode, store: SessionStore) {
        // VIOLATION 1: QR payload flows to SessionStore.storeSession without KEX.
        val payload = barcode.rawValue
        store.storeSession(payload)
    }

    fun provisionIdentityFromQr(zxResult: ZxingResult, store: IdentityKeyStore) {
        // VIOLATION 2: ZXing Result.getText() flows to IdentityKeyStore.saveIdentity
        // without KEX completion.
        val text = zxResult.getText()
        store.saveIdentity(text)
    }

    // Clean control: KEX-completion barrier present.
    fun provisionSafe(barcode: Barcode, store: SessionStore,
                      handshake: NoiseHandshakeState, peer: ByteArray) {
        val payload = barcode.rawValue
        if (!handshake.complete(peer)) {
            return
        }
        store.storeSession(payload)
    }

    class Barcode { val rawValue: String = "" }
    class ZxingResult { fun getText(): String = "" }
    class SessionStore { fun storeSession(payload: String) {} }
    class IdentityKeyStore { fun saveIdentity(text: String) {} }
}
