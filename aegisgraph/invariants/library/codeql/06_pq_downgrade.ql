/**
 * @id aegisgraph/inv-06-pq-downgrade
 * @name InvariantCheck INV-06: Post-quantum KEM silent downgrade
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
 *              ready for when they do. A zero match on a target may
 *              indicate either (a) target lacks PQ entirely (negative
 *              ground truth) or (b) target has PQ and always notifies on
 *              downgrade (positive). The runner reports both.
 * @kind path-problem
 * @problem.severity warning
 * @precision low
 * @id-mapping INV-06
 * @tags security
 *       cryptography
 *       post-quantum
 *       aegisgraph-invariantcheck
 *       mastg-crypto-4
 *       ssdf-pw-4-4
 */

/*
 * Encoding notes:
 *
 *   Sources: hybrid-handshake initiation methods on a *HybridKemHandshake
 *            / *PqxdhSession / *MlsKyber / *PqHandshake type — the
 *            handshake-result strings or capability flags returned to
 *            the caller.
 *
 *   Sinks: branches that select a classical-only handshake (flag
 *          assignment, fallback-helper call) without an intervening
 *          user-notification barrier.
 *
 *   Barriers: user-notification helpers (notifyPqDowngrade,
 *             showPqDowngradeAlert, logPqDowngradeEvent), boolean
 *             SharedPreferences consent records, and event-bus
 *             emissions of *PqDowngradeNotice / *SecurityDowngradeEvent.
 *
 * TODO[ground-truth-pass]: confirm exact Signal PQXDH / Element X MLS
 * class names against pinned commits. PQXDH naming follows the public
 * Signal protocol spec; MLS-with-Kyber naming follows the IETF draft.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.controlflow.Guards
import PqDowngradeFlow::PathGraph

/** A negotiated-handshake result type (`*PqResult`, `*HandshakeResult`, …). */
private predicate handshakeResultType(Type t) {
  t.getName()
      .regexpMatch(".*PqResult.*|.*HandshakeResult.*|.*KemResult.*|.*PqCapabilities.*|.*KemNegotiation.*|.*NegotiationResult.*")
}

/**
 * Reading a flag or field off the handshake result keeps the taint:
 * `pqResult.ok`, `result.getAgreedKem()` (a Kotlin property read is a
 * getter call).
 */
predicate handshakeResultMemberStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(FieldAccess fa |
    handshakeResultType(fa.getQualifier().getType()) and
    pred.asExpr() = fa.getQualifier() and
    succ.asExpr() = fa
  )
  or
  exists(MethodCall mc |
    handshakeResultType(mc.getQualifier().getType()) and
    mc.getMethod().getNumberOfParameters() = 0 and
    pred.asExpr() = mc.getQualifier() and
    succ.asExpr() = mc
  )
}

/** A call into a classical-only handshake helper. */
predicate classicalHandshakeCall(MethodCall mc) {
  mc.getMethod()
      .getDeclaringType()
      .getName()
      .regexpMatch(".*X25519Only.*|.*Curve25519Handshake.*|.*ClassicalHandshake.*|.*LegacyHandshake.*") and
  mc.getMethod().hasName(["initiate", "complete", "perform", "negotiate"])
}

/** A user-visible downgrade notification / consent record. */
predicate downgradeNotificationCall(MethodCall mc) {
  mc.getMethod()
      .hasName([
        "notifyPqDowngrade", "showPqDowngradeAlert",
        "logPqDowngradeEvent", "alertSecurityDowngrade",
        "emitDowngradeNotice", "reportDowngrade",
        "userNotifiedOfDowngrade", "warnPqDowngrade"
      ])
  or
  mc.getMethod().getDeclaringType().hasQualifiedName("android.content", "SharedPreferences$Editor") and
  mc.getMethod().hasName("putBoolean") and
  mc.getArgument(0)
      .(StringLiteral)
      .getValue()
      .regexpMatch("(?i).*pq.*(downgrade|fallback).*consent.*|.*classical.*opt[_-]?in.*")
  or
  mc.getMethod().hasName(["post", "emit", "publish", "send"]) and
  mc.getAnArgument()
      .getType()
      .(RefType)
      .getName()
      .regexpMatch(".*PqDowngradeNotice.*|.*SecurityDowngradeEvent.*|.*DowngradeAlert.*")
}

/**
 * The downgrade DECISION: a condition derived from the handshake result
 * that controls a classical-only handshake call, with no downgrade
 * notification on the same branch. This is control dependency, not data
 * flow — the classical call's arguments (the peer) are never tainted, the
 * *reason* the call runs is. The sink is therefore the condition
 * expression (its tainted sub-expression), and a branch that also
 * notifies the user is not a sink at all.
 */
predicate silentDowngradeDecision(Expr condPart) {
  exists(Guard g, MethodCall classical, boolean branch |
    classicalHandshakeCall(classical) and
    g.controls(classical.getBasicBlock(), branch) and
    condPart = g.(Expr).getAChildExpr*() and
    // One node per decision: the member read (`pqResult.ok`), not also
    // the qualifier it is read from (`pqResult`).
    not exists(MethodCall reader | reader.getQualifier() = condPart) and
    not exists(FieldAccess reader | reader.getQualifier() = condPart) and
    not exists(MethodCall notify |
      downgradeNotificationCall(notify) and
      g.controls(notify.getBasicBlock(), branch)
    )
  )
}

/**
 * Sources: hybrid PQ-handshake initiation outputs.
 */
class HybridHandshakeSource extends DataFlow::Node {
  HybridHandshakeSource() {
    // Method calls on a *HybridKemHandshake / *PqxdhSession / *MlsKyber
    // type returning the handshake capability / algorithm-set result.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*HybridKemHandshake.*|.*PqxdhSession.*|.*PQXDH.*|.*MlsKyber.*|.*MlsKemHandshake.*|.*PqHandshake.*") and
      mc.getMethod()
          .hasName([
            "initiate", "respond", "complete", "negotiateAlgorithms",
            "getAgreedAlgorithms", "getCapabilities", "negotiate",
            "performHandshake"
          ]) and
      this.asExpr() = mc
    )
    or
    // Capability-string / algorithm-name accessors on the negotiated
    // session — these carry the result of the negotiation.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "getKemAlgorithm", "getNegotiatedKem", "getAlgorithmSet",
            "getHandshakeAlgorithms", "getPeerCapabilities",
            "getHybridMode"
          ]) and
      this.asExpr() = mc
    )
    or
    // Top-of-handler parameters typed *HandshakeResult / *Capabilities
    // when handed to a downgrade-decision branch.
    exists(Parameter p |
      p.getType()
          .(RefType)
          .getName()
          .regexpMatch(".*HandshakeResult.*|.*PqCapabilities.*|.*KemNegotiation.*") and
      this.asExpr() = p.getAnAccess()
    )
  }
}

/**
 * Sinks: classical-only-fallback selection points.
 *
 * We match two shapes:
 *   * Boolean / enum flag assignments that turn PQ off:
 *     `useClassicalOnly = true`, `hybridMode = false`,
 *     `pqDisabled = true`, `kemFallback = X25519_ONLY`.
 *   * Calls to a classical-only handshake helper (*X25519Only,
 *     *Curve25519Handshake, *ClassicalHandshake) when reached from a
 *     hybrid-context source.
 */
class ClassicalDowngradeSink extends DataFlow::Node {
  ClassicalDowngradeSink() {
    // Setter on a downgrade-flag field.
    exists(MethodCall mc |
      mc.getMethod()
          .getName()
          .regexpMatch("(?i)set(UseClassicalOnly|PqDisabled|KemFallback|HybridMode|ClassicalMode|DisablePq)") and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // Direct field write into a downgrade-flag field — captured by the
    // assignment target.
    exists(FieldAccess fa, AssignExpr ae |
      ae.getDest() = fa and
      fa.getField()
          .getName()
          .regexpMatch("(?i).*(useClassicalOnly|pqDisabled|kemFallback|hybridMode|classicalMode|disablePq)") and
      this.asExpr() = ae.getSource()
    )
    or
    // Call to a classical-only handshake helper from a hybrid-context
    // source — the handshake result handed straight to the fallback.
    exists(MethodCall mc | classicalHandshakeCall(mc) | this.asExpr() = mc.getAnArgument())
    or
    // The silent downgrade decision itself: `if (!pqResult.ok) return
    // ClassicalHandshake.negotiate(peer)` with no notification on that
    // branch (see silentDowngradeDecision).
    silentDowngradeDecision(this.asExpr())
  }
}

/**
 * Barriers: user-notification helpers and consent records.
 *
 * A downgrade decision that flows through any of these is considered
 * safe (the user is informed, or a prior opt-in has been recorded).
 */
class DowngradeNotificationBarrier extends DataFlow::Node {
  DowngradeNotificationBarrier() {
    // Notification / alert helpers.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "notifyPqDowngrade", "showPqDowngradeAlert",
            "logPqDowngradeEvent", "alertSecurityDowngrade",
            "emitDowngradeNotice", "reportDowngrade",
            "userNotifiedOfDowngrade", "warnPqDowngrade"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
    or
    // SharedPreferences consent record specifically for PQ downgrade.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .hasQualifiedName("android.content", "SharedPreferences$Editor") and
      mc.getMethod().hasName("putBoolean") and
      mc.getArgument(0)
          .(StringLiteral)
          .getValue()
          .regexpMatch("(?i).*pq.*(downgrade|fallback).*consent.*|.*classical.*opt[_-]?in.*") and
      this.asExpr() = mc.getArgument(1)
    )
    or
    // Event-bus emission of a downgrade notice.
    exists(MethodCall mc |
      mc.getMethod().hasName(["post", "emit", "publish", "send"]) and
      mc.getAnArgument()
          .getType()
          .(RefType)
          .getName()
          .regexpMatch(".*PqDowngradeNotice.*|.*SecurityDowngradeEvent.*|.*DowngradeAlert.*") and
      this.asExpr() = mc.getAnArgument()
    )
  }
}

/**
 * Configuration: taint flow from hybrid-handshake initiation sources
 * to classical-downgrade sinks, with notification helpers as barriers.
 */
module PqDowngradeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof HybridHandshakeSource }

  predicate isSink(DataFlow::Node snk) { snk instanceof ClassicalDowngradeSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof DowngradeNotificationBarrier
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    handshakeResultMemberStep(pred, succ)
  }
}

module PqDowngradeFlow = TaintTracking::Global<PqDowngradeConfig>;

from PqDowngradeFlow::PathNode source, PqDowngradeFlow::PathNode sink
where PqDowngradeFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-06: Hybrid PQ-handshake outcome from $@ admits classical-only downgrade without traversing a user-notification barrier.",
  source.getNode(), "this source"
