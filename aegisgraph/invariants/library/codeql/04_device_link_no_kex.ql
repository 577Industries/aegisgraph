/**
 * @id aegisgraph/inv-04-device-link-no-kex
 * @name InvariantCheck INV-04: Device-linking flow lacks key-exchange round-trip (STUB — M7 deliverable)
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
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id-mapping INV-04
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
 * STUB QUERY — NOT YET FULLY ENCODED (M7 deliverable)
 * ─────────────────────────────────────────────────────────────────────
 *
 * This file is committed so the M5.3 manifest entry for INV-04 resolves
 * to a real file on disk. The full encoding is scheduled for M7.
 *
 * Intended encoding sketch (drives the M7 work):
 *
 *   Sources (device-link entry points):
 *     - QR-scan callback inputs (camera intent result), handled in INV-13;
 *       INV-04 picks up the non-camera surface.
 *     - Link-code text-input field commit:
 *         org.signal.devicelink.LinkCodeView.onSubmit
 *         org.matrix.android.sdk.api.devices.DeviceLinkCode.parse
 *     - Magic-link Uri parameter parsing where the host is a known
 *       device-linking host (e.g. signal.org/install, app.element.io/link).
 *
 *   Sinks (device-side state provisioning):
 *     - DeviceRegistrationStore.register / saveDevice
 *     - IdentityKeyStore.saveIdentity / DeviceKeyStore.storeKey
 *     - SessionStore.storeSession on a freshly-issued session
 *     - SyncToken.persist on a newly-issued sync token
 *
 *   Barriers (KEX-completion checks):
 *     - Methods on a *KeyExchange / *X3DH / *NoiseHandshake / *MlsKeyAgreement
 *       type named ["complete", "verify", "finalize", "ratchet",
 *       "confirmRoundTrip"]
 *     - Boolean comparison guards on fields named *kexConfirmed,
 *       *handshakeVerified, *deviceVerified, *linkSecretConfirmed
 *
 *   Configuration:
 *     class DeviceLinkKexConfig extends TaintTracking::Configuration { ... }
 *     module DeviceLinkKexFlow = TaintTracking::Global<DeviceLinkKexConfig>;
 *
 *   Select clause emits: sink, "INV-04: Device-link source from $@ reaches
 *     device-state provisioning without a KEX-completion barrier."
 *
 *   Ground truth (planned):
 *     - demo-vulnerable-app: 1 violation (link-code submit handler that
 *       calls saveDevice() before X3DH.complete()).
 *     - Signal Android / Element X: unknown until the M7 anchor pass.
 *
 * Until this stub is fleshed out, the runner produces an empty SARIF
 * result set for INV-04.
 *
 * See aegisgraph/invariants/manifest.json :: INV-04 for the canonical
 * statement, rationale, MASTG-AUTH-9 / SSDF PW.4.4 mappings.
 *
 * TODO[M7]: Fully encode this query per the spec above. Coordinate the
 * fully-encoded version with INV-13 so the two queries' sources don't
 * overlap (INV-13 owns the QR-camera surface; INV-04 owns the link-code
 * and magic-link surfaces).
 * ─────────────────────────────────────────────────────────────────────
 */

import java

// Trivially-empty query so codeql syntactically accepts the file while
// the stub is in place. select clause produces no results.
from Method m
where none()
select m, "INV-04 stub — see comment block in this file for the M7 encoding plan."
