// Synthetic ground-truth fixture for InvariantCheck INV-04.
// Not based on any real product code.
//
// Expected violations: 1
//   * provisionDevice: LinkCode.parse() flows into DeviceRegistrationStore.register()
//     without a KEX-completion barrier.
//
// Clean control: provisionDeviceWithKex uses NoiseHandshakeState.complete barrier.
package com.example.demo;

import com.example.fixtures.KexCompletion.NoiseHandshakeState;

public class DeviceLinkNoKex {

    public void provisionDevice(String linkCodeText, DeviceRegistrationStore store) {
        // VIOLATION 1: LinkCode.parse output flows to device-register without KEX.
        LinkCode code = LinkCode.parse(linkCodeText);
        store.register(code.deviceId);
    }

    // Clean control: KEX-completion barrier present.
    public void provisionDeviceWithKex(String linkCodeText, DeviceRegistrationStore store,
                                       NoiseHandshakeState handshake, byte[] peerEphemeral) {
        LinkCode code = LinkCode.parse(linkCodeText);
        if (!handshake.complete(peerEphemeral)) {
            return;
        }
        store.register(code.deviceId);
    }

    public static class LinkCode {
        public String deviceId = "";
        public static LinkCode parse(String text) { return new LinkCode(); }
    }

    public static class DeviceRegistrationStore {
        public void register(String deviceId) {}
    }
}
