/**
 * @id aegisgraph/inv-06-pq-downgrade
 * @name InvariantCheck INV-06: Post-quantum KEM silent downgrade (STUB — M7 deliverable)
 * @description Post-quantum KEM handshake protocols must not silently
 *              downgrade to classical-only (e.g. X25519 without
 *              Kyber768 hybrid) without a user-visible notification or
 *              session-level opt-in record. A silent downgrade strips
 *              harvest-now-decrypt-later resistance without notifying
 *              the user, defeating the purpose of the PQ deployment.
 *
 *              This invariant becomes critical as Signal's PQXDH and
 *              Matrix's MLS-with-Kyber rollouts mature; today's targets
 *              may not yet exhibit the surface, but the encoding is
 *              ready for when they do.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id-mapping INV-06
 * @tags security
 *       cryptography
 *       post-quantum
 *       aegisgraph-invariantcheck
 *       mastg-crypto-4
 *       ssdf-pw-4-4
 *       stub
 */

/*
 * ─────────────────────────────────────────────────────────────────────
 * STUB QUERY — NOT YET FULLY ENCODED (M7 deliverable)
 * ─────────────────────────────────────────────────────────────────────
 *
 * This file is committed so the M5.3 manifest entry for INV-06 resolves
 * to a real file on disk. The full encoding is scheduled for M7 (or
 * later, once the targets actually ship hybrid PQ).
 *
 * Intended encoding sketch (drives the M7 work):
 *
 *   Sources (hybrid handshake entry points):
 *     - PQXDH.initiate / PQXDH.respond (Signal PQXDH library)
 *     - MlsKemHandshake.initiate (Matrix MLS-with-Kyber)
 *     - Methods on a *HybridKemHandshake / *PqxdhSession / *MlsKyber
 *       type named ["initiate", "respond", "complete"]
 *
 *   Sinks (downgrade-decision points):
 *     - Branches that set a flag named *useClassicalOnly,
 *       *pqDisabled, *kemFallback, *hybridMode=false
 *     - Calls to a classical-only handshake helper named *X25519Only,
 *       *Curve25519Handshake when invoked from a path that started in
 *       a hybrid context
 *
 *   Barriers (user-notification / consent records):
 *     - notifyPqDowngrade / showPqDowngradeAlert / logPqDowngradeEvent
 *     - SharedPreferences.Editor.putBoolean("pq_downgrade_consented",
 *       true)
 *     - Event-bus emission of a PqDowngradeNotice / SecurityDowngradeEvent
 *
 *   Configuration:
 *     class PqDowngradeConfig extends TaintTracking::Configuration { ... }
 *     module PqDowngradeFlow = TaintTracking::Global<PqDowngradeConfig>;
 *
 *   Select clause emits: sink, "INV-06: PQ handshake from $@ admits
 *     classical-only downgrade without user-notification barrier."
 *
 *   Ground truth (planned):
 *     - demo-vulnerable-app: 1 violation (a contrived hybrid handshake
 *       that flips to X25519-only on capability mismatch without
 *       notifying the user).
 *     - Signal Android / Element X: unknown (Signal PQXDH does notify;
 *       worth verifying with the encoding).
 *
 * Until this stub is fleshed out, the runner produces an empty SARIF
 * result set for INV-06.
 *
 * See aegisgraph/invariants/manifest.json :: INV-06 for the canonical
 * statement, rationale, MASTG-CRYPTO-4 / SSDF PW.4.4 mappings.
 *
 * TODO[M7]: Fully encode this query per the spec above. Be mindful that
 * the target SMAs may not yet emit hybrid-handshake code in the anchor
 * commits; if the query matches zero call sites on a target, that is
 * itself a useful observability signal (target lacks PQ entirely vs
 * target has PQ but downgrades).
 * ─────────────────────────────────────────────────────────────────────
 */

import java

// Trivially-empty query so codeql syntactically accepts the file while
// the stub is in place. select clause produces no results.
from Method m
where none()
select m, "INV-06 stub — see comment block in this file for the M7 encoding plan."
