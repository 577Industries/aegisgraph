// Synthetic ground-truth fixture for InvariantCheck library v3.
// Not based on any real product code.
//
// Shared "good" KEX completion barrier referenced by INV-04 / INV-13
// clean controls. The CodeQL queries recognize the *KeyExchange /
// *NoiseHandshake declaring type + complete/verify/finalize/ratchet
// method names as taint barriers.
package com.example.fixtures;

public final class KexCompletion {

    public static final class NoiseHandshakeState {
        private boolean kexConfirmed;

        public boolean complete(byte[] peerEphemeral) {
            this.kexConfirmed = peerEphemeral != null && peerEphemeral.length == 32;
            return this.kexConfirmed;
        }

        public boolean verify(byte[] mac) {
            return this.kexConfirmed && mac != null;
        }

        public boolean isHandshakeComplete() {
            return this.kexConfirmed;
        }
    }

    public static final class X3DHKeyExchange {
        public boolean finalize(byte[] peerIdentity, byte[] peerEphemeral) {
            return peerIdentity != null && peerEphemeral != null;
        }
    }
}
