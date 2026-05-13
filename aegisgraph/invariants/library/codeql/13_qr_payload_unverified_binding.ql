/**
 * @id aegisgraph/inv-13-qr-payload-unverified-binding
 * @name InvariantCheck INV-13: QR payload unverified binding
 * @description QR-code-initiated device linking flows must bind the QR
 *              payload to a verified key-exchange round-trip (X3DH,
 *              Noise, or MLS keypair confirmation) before any session
 *              key, identity claim, or sync token is provisioned. A
 *              missing or short-circuited KEX-completion barrier lets a
 *              tampered or relay-MITM'd QR silently link an attacker
 *              device to a victim account.
 *
 *              Closely related to INV-04 (device-link no kex); INV-13
 *              covers the camera/scanner-initiated QR surface
 *              specifically (Barcode.getRawValue, ZXing Result.getText,
 *              Signal QrUrl.parse, Matrix QrCodePayload.fromBytes).
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id-mapping INV-13
 * @tags security
 *       external-input
 *       crypto-key-lifecycle
 *       aegisgraph-invariantcheck
 *       mastg-auth-9
 *       ssdf-pw-4-4
 */

/*
 * Encoding notes:
 *
 *   Sources: QR-decoded strings — ML Kit Barcode.getRawValue, ZXing
 *            com.google.zxing.Result.getText, Signal QrUrl.parse,
 *            Matrix QrCodePayload.from* / .fromBytes.
 *
 *   Sinks: device-link provisioning APIs — SessionStore.storeSession
 *          (Signal libsignal), MXCryptoStore.storeSession (Matrix
 *          android sdk), IdentityKeyStore.saveIdentity, and
 *          sync-state initializers that consume a deviceId.
 *
 *   Barriers: KEX-completion predicates — methods on a *KeyExchange /
 *             *X3DH / *NoiseHandshake / *MlsKeyAgreement type named
 *             complete / verify / finalize / ratchet; boolean reads of
 *             *kexConfirmed / *handshakeVerified / *deviceVerified.
 *
 * TODO[ground-truth-pass]: confirm exact Signal libsignal SessionStore
 * and Matrix android-sdk MXCryptoStore class names against pinned
 * commits. The placeholder fully-qualified names below
 * (org.signal.libsignal.protocol.state.SessionStore,
 * org.matrix.android.sdk.api.session.crypto.crosssigning.MXCryptoStore)
 * are structural and will be pinned in the M7-GT pass.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

/**
 * Sources: QR-decoded string outputs.
 */
class QrPayloadSource extends DataFlow::Node {
  QrPayloadSource() {
    // ML Kit: com.google.mlkit.vision.barcode.common.Barcode.getRawValue().
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*Barcode.*") and
      mc.getMethod()
          .hasName(["getRawValue", "getDisplayValue", "getRawBytes"]) and
      this.asExpr() = mc
    )
    or
    // ZXing: com.google.zxing.Result.getText() / getRawBytes().
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("com.google.zxing", "Result") and
      mc.getMethod()
          .hasName(["getText", "getRawBytes"]) and
      this.asExpr() = mc
    )
    or
    // Signal QrUrl.parse — TODO[ground-truth-pass]: confirm exact
    // Signal/Element X class names against pinned commit.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*QrUrl.*|.*QRUrl.*|.*QrCodePayload.*|.*QRCodePayload.*|.*ProvisioningQr.*") and
      mc.getMethod()
          .hasName(["parse", "from", "fromBytes", "fromString", "decode", "deserialize"]) and
      this.asExpr() = mc
    )
    or
    // Generic QR-scan result strings from a typed scan-result parameter.
    exists(Parameter p |
      p.getType()
          .(RefType)
          .getName()
          .regexpMatch(".*QrScanResult.*|.*QRScanResult.*|.*ScannedCode.*|.*BarcodeScanResult.*") and
      this.asExpr() = p.getAnAccess()
    )
  }
}

/**
 * Sinks: device-link provisioning calls that consume the QR payload.
 */
class DeviceLinkProvisioningSink extends DataFlow::Node {
  DeviceLinkProvisioningSink() {
    // SessionStore.storeSession — Signal libsignal.
    // TODO[ground-truth-pass]: confirm exact Signal/Element X class names
    // against pinned commit.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*SessionStore.*|.*SessionDatabase.*") and
      mc.getMethod()
          .hasName(["storeSession", "saveSession", "putSession"]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // MXCryptoStore.storeSession — Matrix android sdk.
    // TODO[ground-truth-pass]: confirm exact class names.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*MXCryptoStore.*|.*CryptoStore.*|.*OlmSessionStore.*") and
      mc.getMethod()
          .hasName(["storeSession", "storeInboundGroupSessions", "saveSession"]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // IdentityKeyStore.saveIdentity — libsignal-style identity-key
    // registration.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*IdentityKeyStore.*|.*IdentityStore.*") and
      mc.getMethod()
          .hasName(["saveIdentity", "putIdentity", "registerIdentity"]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // Sync-state initializers that consume a deviceId or device payload.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*SyncState.*|.*SyncTokenStore.*|.*DeviceSyncState.*") and
      mc.getMethod()
          .hasName(["initialize", "setDeviceId", "bindDevice", "provisionDevice"]) and
      this.asExpr() = mc.getAnArgument()
    )
  }
}

/**
 * Barriers: KEX-completion predicates and verified-handshake flags.
 */
class KexCompletionBarrier extends DataFlow::Node {
  KexCompletionBarrier() {
    // Methods on a *KeyExchange / *X3DH / *NoiseHandshake /
    // *MlsKeyAgreement type named complete / verify / finalize / ratchet.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*KeyExchange.*|.*X3DH.*|.*PQXDH.*|.*NoiseHandshake.*|.*MlsKeyAgreement.*|.*MlsHandshake.*|.*HandshakeState.*|.*DeviceVerification.*") and
      mc.getMethod()
          .hasName([
            "complete", "verify", "finalize", "ratchet",
            "confirmRoundTrip", "checkComplete", "isComplete",
            "verifyEphemeral", "verifyHandshake", "completeProvisioning"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // Boolean field reads on a *kexConfirmed / *handshakeVerified /
    // *deviceVerified flag.
    exists(FieldAccess fa |
      fa.getField()
          .getName()
          .regexpMatch("(?i).*(kex|handshake|device|provisioning)(Confirmed|Verified|Complete|Done|Ready)") and
      this.asExpr() = fa
    )
    or
    // Generic name-based barrier helpers in the device-linking code.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "isHandshakeComplete", "verifyKex", "assertKexComplete",
            "ensureLinkVerified", "verifyDeviceLink", "verifyQrPayloadBinding",
            "assertDeviceVerified"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
  }
}

/**
 * Configuration: taint flow from QR-payload sources to device-link
 * provisioning sinks, with KEX-completion barriers as sanitizers.
 */
module QrPayloadBindingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof QrPayloadSource }

  predicate isSink(DataFlow::Node snk) { snk instanceof DeviceLinkProvisioningSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof KexCompletionBarrier }
}

module QrPayloadBindingFlow = TaintTracking::Global<QrPayloadBindingConfig>;

from QrPayloadBindingFlow::PathNode source, QrPayloadBindingFlow::PathNode sink
where QrPayloadBindingFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-13: QR payload from $@ reaches device-link provisioning without KEX-completion barrier.",
  source.getNode(), "this source"
