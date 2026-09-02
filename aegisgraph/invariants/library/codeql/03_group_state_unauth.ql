/**
 * @id aegisgraph/inv-03-group-state-unauth
 * @name InvariantCheck INV-03: Group-state mutation without sender authorization
 * @description Group-event handlers (add member, change admin, change
 *              avatar, rotate sender key) must verify the sender's
 *              authorization role and current group membership against
 *              the local group-state authority before mutating local
 *              state. A handler that accepts a group event without that
 *              check is exposed to relayed or replayed
 *              group-management events from removed or non-admin members,
 *              causing silent group-composition tampering.
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id-mapping INV-03
 * @tags security
 *       external-input
 *       sync-state
 *       aegisgraph-invariantcheck
 *       mastg-auth-2
 *       ssdf-pw-4-4
 */

/*
 * Encoding notes:
 *
 *   Sources: inbound group-event accessors on a *GroupEvent / *Event /
 *            *GroupV2Update / *GroupChange typed payload. We recognize
 *            both the Signal lineage (getGroupChange, getMembers,
 *            getModifyMemberRolesAction) and the Matrix lineage
 *            (getStateKey, getContent, getMembershipEvent).
 *
 *   Sinks: state-mutating writes inside the same handler — GroupDatabase
 *          updates, SenderKeyStore stores, Room/Group setters.
 *
 *   Barriers: sender-role / sender-membership predicates. We accept any
 *             method whose name matches a role-check pattern
 *             (isAdmin, hasPermissionToMutate, isAuthorizedSender,
 *             requireAdminPermission, checkGroupAdminRole) or any
 *             comparison against an admin-role constant.
 *
 * TODO[ground-truth-pass]: Signal-android and Element-X class names below
 * are placeholders rooted in public-protocol naming. The M7-GT pass
 * pins these against the actual class names in the anchored commits
 * (signal_android@1043851 / elementx_android@91d265e6) and prunes
 * false positives.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.controlflow.Guards
import GroupStateUnauthFlow::PathGraph

/** A sender-role / membership check call. */
predicate roleCheckCall(MethodCall mc) {
  mc.getMethod()
      .hasName([
        "isAdmin", "isCoAdmin", "isModerator", "isOwner",
        "hasPermissionToMutate", "isGroupMember", "isAuthorizedSender",
        "checkGroupAdminRole", "requireAdminPermission", "verifyAdminRole",
        "verifySenderRole", "verifyMembership", "isSenderAdmin",
        "canModifyGroup", "canKickMember", "hasAdminRole",
        "isAuthorizedToChange", "requireAdmin", "assertSenderIsAdmin"
      ])
  or
  mc.getMethod()
      .getDeclaringType()
      .getName()
      .regexpMatch(".*GroupAuthority.*|.*PermissionChecker.*|.*RoleChecker.*|.*AccessControl.*")
}

/**
 * A mutation that only runs once a role check has evaluated to true
 * (`if (!event.verifyAdminRole()) return` and then the write) is
 * guarded. Every access of the handler's payload parameter is a source,
 * so a data-flow barrier on the checked access cannot cover the later
 * accesses; the guard on the sink can.
 */
predicate roleGuardedSink(DataFlow::Node snk) {
  exists(Guard g |
    roleCheckCall(g) and
    g.controls(snk.asExpr().getBasicBlock(), true)
  )
}

/**
 * Sources: inbound group-event payload accessors.
 *
 * We name-match getters on payload types that messenger codebases
 * expose for group-management events. The list draws from Signal's
 * GroupV2 update lineage and Matrix's m.room.member /
 * m.room.power_levels event handlers.
 *
 * TODO[ground-truth-pass]: confirm exact Signal/Element X class names
 * against pinned commit; today we match by method name to keep the
 * query target-agnostic.
 */
class GroupEventSource extends DataFlow::Node {
  GroupEventSource() {
    // Signal-lineage group-event getters.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "getGroupChange", "getModifyMemberRolesAction",
            "getAddMembersAction", "getDeleteMembersAction",
            "getModifyTitleAction", "getModifyAvatarAction",
            "getRotateSenderKeyAction", "getGroupMasterKey",
            "getModifyMemberAccessControlAction",
            "getPromotePendingMembersAction"
          ]) and
      this.asExpr() = mc
    )
    or
    // Matrix-lineage state-event getters.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "getStateKey", "getMembershipEvent", "getPowerLevelsContent",
            "getRoomMemberContent", "getRoomCreateContent",
            "getRoomJoinRulesContent"
          ]) and
      this.asExpr() = mc
    )
    or
    // Top-level parameter access on a handler that takes a typed
    // group-event payload (e.g. `void handleAddMember(GroupV2Update u)`,
    // `fun applyGroupAddMember(event: GroupAddMemberEvent, …)`).
    exists(Parameter p |
      groupEventType(p.getType()) and
      this.asExpr() = p.getAnAccess()
    )
  }
}

/**
 * A group-management event payload type: `Group…Update` / `…Change` /
 * `…Event` / `…Action` with any words in between, or the Matrix
 * membership / member-content shapes.
 */
private predicate groupEventType(Type t) {
  t.getName()
      .regexpMatch(".*Group.*(Update|Change|Event|Action).*|.*MembershipEvent.*|.*RoomMemberContent.*")
}

/**
 * Data read out of a tainted group-event payload stays tainted: field
 * reads and no-arg getters (which is what a Kotlin property read
 * compiles to — `event.memberId` is `getMemberId()`).
 */
predicate groupEventMemberStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(FieldAccess fa |
    groupEventType(fa.getQualifier().getType()) and
    pred.asExpr() = fa.getQualifier() and
    succ.asExpr() = fa
  )
  or
  exists(MethodCall mc |
    groupEventType(mc.getQualifier().getType()) and
    mc.getMethod().getNumberOfParameters() = 0 and
    not mc.getMethod().getReturnType() instanceof BooleanType and
    pred.asExpr() = mc.getQualifier() and
    succ.asExpr() = mc
  )
}

/**
 * Sinks: state-mutating writes inside the same handler.
 *
 * We match GroupDatabase / RoomDatabase / SenderKeyStore /
 * LocalGroupAuthority methods that persist a change.
 */
class GroupStateMutationSink extends DataFlow::Node {
  GroupStateMutationSink() {
    // GroupDatabase / RoomDatabase / GroupStateStore mutation methods.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*GroupDatabase.*|.*RoomDatabase.*|.*GroupTable.*|.*LocalGroupAuthority.*|.*GroupState.*|.*GroupStore.*|.*GroupRepository.*") and
      mc.getMethod()
          .hasName([
            "updateMembers", "addMember", "removeMember",
            "updatePowerLevels", "setRole", "applyChange",
            "applyGroupChange", "updateTitle", "setAvatar",
            "rename", "rotateSenderKey", "promoteMember",
            "demoteMember", "bulkInsert", "insert", "update", "delete"
          ]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // SenderKeyStore.storeSenderKey when invoked from a group-event
    // handler — name match catches both Signal and libsignal shapes.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*SenderKeyStore.*|.*SenderKeyDatabase.*") and
      mc.getMethod()
          .hasName(["storeSenderKey", "saveSenderKey", "putSenderKey"]) and
      this.asExpr() = mc.getAnArgument()
    )
    or
    // RoomMember / Group setters on the model object — direct mutation
    // through model state without going through the database layer.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*RoomMember.*|.*GroupMember.*|.*Group$") and
      mc.getMethod()
          .hasName(["setRole", "setAvatar", "rename", "setName", "setMembership"]) and
      this.asExpr() = mc.getAnArgument()
    )
  }
}

/**
 * Barriers: sender-role / sender-membership predicates.
 *
 * A value passing through any of these checks is considered safe to
 * propagate to the mutation sink.
 */
class SenderAuthorizationBarrier extends DataFlow::Node {
  SenderAuthorizationBarrier() {
    // Direct role-check method names — covers most messenger lineages.
    // The check's QUALIFIER is a barrier too: `event.verifyAdminRole()`
    // validates the event itself, so every later read of that event
    // (`event.memberId` on the next line) is covered through the
    // use-use chain.
    exists(MethodCall mc |
      mc.getMethod()
          .hasName([
            "isAdmin", "isCoAdmin", "isModerator", "isOwner",
            "hasPermissionToMutate", "isGroupMember", "isAuthorizedSender",
            "checkGroupAdminRole", "requireAdminPermission", "verifyAdminRole",
            "verifySenderRole", "verifyMembership", "isSenderAdmin",
            "canModifyGroup", "canKickMember", "hasAdminRole",
            "isAuthorizedToChange", "requireAdmin", "assertSenderIsAdmin"
          ]) and
      this.asExpr() = [mc, mc.getAnArgument(), mc.getQualifier()]
    )
    or
    // Field/enum comparison against a role constant — handles the
    // `if (sender.role == Role.ADMIN)` shape.
    exists(FieldAccess fa |
      fa.getField()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*Role|.*PowerLevel|.*Membership") and
      fa.getField()
          .getName()
          .regexpMatch("(?i)ADMIN|OWNER|MODERATOR|CO_ADMIN") and
      this.asExpr() = fa
    )
    or
    // Methods on a *GroupAuthority / *PermissionChecker type — once a
    // sender has been validated by such a helper, taint clears.
    exists(MethodCall mc |
      mc.getMethod()
          .getDeclaringType()
          .getName()
          .regexpMatch(".*GroupAuthority.*|.*PermissionChecker.*|.*RoleChecker.*|.*AccessControl.*") and
      this.asExpr() = [mc, mc.getAnArgument()]
    )
  }
}

/**
 * Configuration: taint flow from group-event payload sources to
 * group-state mutation sinks, with sender-authorization predicates as
 * barriers.
 */
module GroupStateUnauthConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof GroupEventSource }

  predicate isSink(DataFlow::Node snk) {
    snk instanceof GroupStateMutationSink and not roleGuardedSink(snk)
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof SenderAuthorizationBarrier
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    groupEventMemberStep(pred, succ)
  }
}

module GroupStateUnauthFlow = TaintTracking::Global<GroupStateUnauthConfig>;

from GroupStateUnauthFlow::PathNode source, GroupStateUnauthFlow::PathNode sink
where GroupStateUnauthFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "INV-03: Group-event payload from $@ reaches group-state mutation without traversing a sender-authorization barrier.",
  source.getNode(), "this source"
