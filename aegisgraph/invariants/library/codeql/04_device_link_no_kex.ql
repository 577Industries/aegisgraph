/**
 * @id aegisgraph/inv-04-device-link-no-kex
 * @name InvariantCheck INV-04: Device-linking flow lacks key-exchange round-trip
 * @description Device-linking flows (QR scan, link code, magic-link) must
 *              not provision device-side key material, session state, or
 *              sync tokens without completing a key-exchange round-trip
 *              (X3DH, Noise, MLS handshake) that authenticates both
 *              endpoints. Provisioning without a KEX silently links an
 *              attacker device to a victim account via a tampered,
 *              relayed, or social-engineered linking primitive.
 *
 *              Closely related to INV-13 (QR payload unverified binding);
 *              INV-04 covers the link-code / magic-link / app-clip surface
 *              that doesn't require a camera.
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id-mapping INV-04
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
 *   Sources: link-code text-input commits, magic-link Uri parameters,
 *            and QR-scan callback strings (the QR-camera surface is
 *            primarily INV-13's responsibility but is also matched here
 *            for defense-in-depth — duplicate findings are deduplicated
 *            by the consolidator using location keys).
 *
 *   Sinks: device-side provisioning calls — DeviceRegistrationStore,
 *          IdentityKeyStore, SessionStore, SyncToken persistence.
 *
 *   Barriers: KEX-completion predicates — methods on a *KeyExchange /
 *             *X3DH / *NoiseHandshake / *MlsKeyAgreement type named
 *             complete / verify / finalize / ratchet / confirmRoundTrip;
 *             field comparisons against kexConfirmed-style booleans.
 *
 * TODO[ground-truth-pass]: confirm Signal-android DeviceRegistrationStore
 * and Element-X DeviceLinkCode class names against pinned commits.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DeviceLinkKexFlow::PathGraph

/**
 * Sources: device-linking entry points.
 *
 * Three shapes:
 *   * Link-code text submitted via a *LinkCodeView / *DeviceLinkCode
 *     parse/submit method.
 *   * Magic-link Uri parameters extracted from an inbound Intent on a
 *     known device-linking host.
 *   * QR-scan camera-intent result strings — overlaps INV-13 by design.
 */
class DeviceLinkSource extends DataFlow::Node {
  DeviceLinkSource() {
    // Link-code parse / submit methods (Signal / Element naming).
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*LinkCode.*|.*DeviceLinkCode.*|.*LinkCodeView.*|.*ProvisioningCode.*") and
      mc.getMethod()
          .hasName(["parse", "submit", "onSubmit", "verify", "decode", "fromString"]) and
      this.asExpr() = mc
    )
    or
    // Magic-link Uri parameter extraction via getQueryParameter on a
    // device-linking host.
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("android.net", "Uri") and
      mc.getMethod()
          .hasName(["getQueryParameter", "getQueryParameters", "getFragment", "getPath"]) and
      this.asExpr() = mc
    )
    or
    // QR-scan result strings — ML Kit Barcode / ZXing Result.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*Barcode.*|.*QRResult.*|.*BarcodeScanner.*|.*ScanResult.*|com\\.google\\.zxing\\..*") and
      mc.getMethod()
          .hasName(["getRawValue", "getDisplayValue", "getText", "getContents"]) and
      this.asExpr() = mc
    )
    or
    // Top-of-handler parameters typed *ProvisioningEnvelope /
    // *DeviceLinkPayload.
    exists(Parameter p |
      p.getType()
          .(RefType)
          .getName()
          .regexpMatch(".*ProvisioningEnvelope.*|.*DeviceLinkPayload.*|.*ProvisionMessage.*|.*LinkRequest.*") and
      this.asExpr() = p.getAnAccess()
    )
  }
}

/**
 * Sinks: device-side provisioning calls.
 */
class DeviceProvisioningSink extends DataFlow::Node {
  DeviceProvisioningSink() {
    // Device registration writes.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*DeviceRegistration.*|.*DeviceStore.*|.*DeviceTable.*") and
      mc.getMethod()
          .hasName(["register", "saveDevice", "addDevice", "persistDevice", "storeDevice"]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // Identity-key / device-key persistence (libsignal-style).
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*IdentityKeyStore.*|.*DeviceKeyStore.*|.*ProvisioningKeyStore.*") and
      mc.getMethod()
          .hasName(["saveIdentity", "storeKey", "putIdentity", "saveDeviceKey"]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // Session-store provisioning for a newly-issued session.
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
    // Sync-token persistence.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*SyncToken.*|.*SyncStateStore.*") and
      mc.getMethod()
          .hasName(["persist", "save", "store"]) and
      this.asExpr() = mc.getAnArgument()
    )
  }
}

/**
 * Barriers: KEX-completion predicates and verified-handshake guards.
 */
class KexCompletionBarrier extends DataFlow::Node {
  KexCompletionBarrier() {
    // Method calls on a *KeyExchange / *X3DH / *Noise / *MLS / *PQXDH
    // type named complete / verify / finalize / ratchet.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*KeyExchange.*|.*X3DH.*|.*PQXDH.*|.*NoiseHandshake.*|.*MlsKeyAgreement.*|.*MlsHandshake.*|.*HandshakeState.*") and
      mc.getMethod()
          .hasName([
            "complete", "verify", "finalize", "ratchet",
            "confirmRoundTrip", "checkComplete", "isComplete",
            "verifyEphemeral", "verifyHandshake"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // Boolean field access for a *kexConfirmed / *handshakeVerified flag.
    exists(FieldAccess fa |
      fa.getField()
          .getName()
          .regexpMatch("(?i).*(kex|handshake|provisioning|deviceLink)(Confirmed|Verified|Complete|Done)") and
      this.asExpr() = fa
    )
    or
    // Generic name-based barrier — explicit barrier helpers in the
    // device-linking code.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "isHandshakeComplete", "verifyKex", "assertKexComplete",
            "ensureLinkVerified", "verifyDeviceLink", "verifyProvisioningEnvelope"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
  }
}

/**
 * Configuration: taint flow from device-link sources to device-
 * provisioning sinks, with KEX-completion predicates as barriers.
 */
module DeviceLinkKexConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof DeviceLinkSource }

  predicate isSink(DataFlow::Node snk) { snk instanceof DeviceProvisioningSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof KexCompletionBarrier }
}

module DeviceLinkKexFlow = TaintTracking::Global<DeviceLinkKexConfig>;

from DeviceLinkKexFlow::PathNode source, DeviceLinkKexFlow::PathNode sink
where DeviceLinkKexFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-04: Device-link payload from $@ reaches device-provisioning sink without traversing a KEX-completion barrier.",
  source.getNode(), "this source"
