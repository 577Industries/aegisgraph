// Synthetic ground-truth fixture for InvariantCheck INV-06.
// Not based on any real product code.
//
// Expected violations: 1
//   * negotiateHandshake: PqHandshake.negotiate falls back to classical-only
//     when peer rejects Kyber, without notifying the user.
//
// Clean control: negotiateHandshakeNotify emits NotifyDowngrade.
package com.example.demo

class PqDowngrade {

    fun negotiateHandshake(peer: Peer): SessionKeys {
        // VIOLATION 1: silent downgrade to classical-only — no user notification
        // path between the fallback branch and the returned classical session.
        val pqResult = PqHandshake.negotiate(peer)
        if (!pqResult.ok) {
            return ClassicalHandshake.negotiate(peer)
        }
        return pqResult.keys
    }

    // Clean control: user-visible downgrade notification on the fallback path.
    fun negotiateHandshakeNotify(peer: Peer, notifier: DowngradeNotifier): SessionKeys {
        val pqResult = PqHandshake.negotiate(peer)
        if (!pqResult.ok) {
            notifier.notifyPqDowngrade(peer.id)
            return ClassicalHandshake.negotiate(peer)
        }
        return pqResult.keys
    }

    class Peer { val id: String = "" }
    class SessionKeys
    class PqResult { val ok: Boolean = false; val keys: SessionKeys = SessionKeys() }
    object PqHandshake { fun negotiate(p: Peer): PqResult = PqResult() }
    object ClassicalHandshake { fun negotiate(p: Peer): SessionKeys = SessionKeys() }
    class DowngradeNotifier { fun notifyPqDowngrade(peerId: String) {} }
}
