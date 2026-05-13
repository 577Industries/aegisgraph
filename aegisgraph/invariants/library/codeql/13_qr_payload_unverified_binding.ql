/**
 * @id aegisgraph/inv-13-qr-payload-unverified-binding
 * @name InvariantCheck INV-13: QR payload unverified binding (STUB — M3.4 deliverable)
 * @description QR-code-initiated device linking flows must bind the QR
 *              payload to a verified key-exchange round-trip (X3DH,
 *              Noise, or MLS keypair confirmation) before any session
 *              key, identity claim, or sync token is provisioned. A
 *              missing or short-circuited KEX-completion barrier lets a
 *              tampered or relay-MITM'd QR silently link an attacker
 *              device to a victim account.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id-mapping INV-13
 * @tags security
 *       external-input
 *       crypto-key-lifecycle
 *       aegisgraph-invariantcheck
 *       mastg-auth-9
 *       ssdf-pw-4-4
 *       stub
 */

/*
 * ─────────────────────────────────────────────────────────────────────
 * STUB QUERY — NOT YET FULLY ENCODED (M3.4 deliverable)
 * ─────────────────────────────────────────────────────────────────────
 *
 * This file is committed so the M3.3 manifest entry for INV-13 resolves
 * to a real file on disk. The full encoding is scheduled for M3.4.
 *
 * Intended encoding sketch (do not delete — drives the M3.4 work):
 *
 *   Sources:
 *     - com.google.mlkit.vision.barcode.Barcode.getRawValue()
 *     - com.google.zxing.Result.getText()
 *     - String values extracted from QR-decoded image bytes where the
 *       enclosing method is annotated / named *QRCode* / *DeviceLink*
 *     - org.signal.devicelink.QrUrl.parse(...) (Signal-specific)
 *     - io.element.android.qrcode.QrCodePayload (Element X / Matrix-specific)
 *
 *   Sinks:
 *     - calls into a session-keystore provisioning API:
 *         * org.signal.libsignal.protocol.state.SessionStore.storeSession
 *         * org.matrix.android.sdk.api.session.crypto.MXCryptoStore.storeSession
 *     - identity-key registration:
 *         * IdentityKey.register / IdentityKeyStore.saveIdentity
 *     - sync-state initializers that accept a freshly-derived device id
 *
 *   Barriers (KEX-completion checks):
 *     - Methods on a *KeyExchange / *X3DH / *NoiseHandshake / *MlsKeyAgreement
 *       type named ["complete", "verify", "finalize", "ratchet"]
 *     - Boolean comparison guards on a field named *kexConfirmed,
 *       *handshakeVerified, *deviceVerified
 *
 *   Configuration:
 *     class QrPayloadBindingConfig extends TaintTracking::Configuration
 *
 *   Select clause emits: sink, "INV-13: QR payload from $@ reaches
 *     device-link provisioning without KEX-completion barrier."
 *
 * Until this stub is fleshed out, the runner produces an empty SARIF
 * result set for INV-13. The manifest entry truthfully records
 * `expected_violations: "unknown"` and ground-truth assertion lands
 * with the full encoding at M3.4 (demo-vulnerable-app fixture) and
 * with M5.4 against Signal / Element X anchors.
 *
 * See aegisgraph/invariants/manifest.json :: INV-13 for the canonical
 * statement, rationale, and MASTG / SSDF mapping.
 * ─────────────────────────────────────────────────────────────────────
 */

import java

// Trivially-empty query so codeql syntactically accepts the file while
// the stub is in place. select clause produces no results.
from Method m
where none()
select m, "INV-13 stub — see comment block in this file for the M3.4 encoding plan."
