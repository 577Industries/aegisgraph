/**
 * @id aegisgraph/inv-03-group-state-unauth
 * @name InvariantCheck INV-03: Group-state mutation without sender authorization (STUB — M7 deliverable)
 * @description Group-event handlers (add member, change admin, change
 *              avatar, rotate sender key) must verify the sender's
 *              authorization role and current group membership against
 *              the local group-state authority before mutating local
 *              state. A handler that accepts a group event without that
 *              check is exposed to relayed or replayed
 *              group-management events from removed or non-admin members,
 *              causing silent group-composition tampering.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id-mapping INV-03
 * @tags security
 *       external-input
 *       sync-state
 *       aegisgraph-invariantcheck
 *       mastg-auth-2
 *       ssdf-pw-4-4
 *       stub
 */

/*
 * ─────────────────────────────────────────────────────────────────────
 * STUB QUERY — NOT YET FULLY ENCODED (M7 deliverable)
 * ─────────────────────────────────────────────────────────────────────
 *
 * This file is committed so the M5.3 manifest entry for INV-03 resolves
 * to a real file on disk. The full encoding is scheduled for M7
 * (alongside the ground-truth pass against demo-vulnerable-app fixtures
 * and the Signal / Element X anchor commits).
 *
 * Intended encoding sketch (drives the M7 work):
 *
 *   Sources (group-event handler entry points):
 *     - Methods named *handleGroupV2Update / *handleGroupCreate /
 *       *handleAddMember / *handleRemoveMember / *handleChangeAdmin /
 *       *handleAvatarChange / *handleRotateSenderKey on a *Receiver,
 *       *Service, or *Handler type
 *     - Methods annotated with @Subscribe / @OnGroupEvent (EventBus / RxBus
 *       wiring patterns)
 *     - Top-of-handler parameters typed
 *       org.signal.libsignal.groups.GroupV2Update,
 *       org.matrix.android.sdk.api.session.events.model.Event (for
 *       Matrix's m.room.member / m.room.power_levels handlers)
 *
 *   Sinks (state-mutating side effects in the same handler):
 *     - GroupDatabase.updateMembers / RoomDatabase.updatePowerLevels /
 *       LocalGroupAuthority.applyChange
 *     - SenderKeyStore.storeSenderKey when invoked inside a group-event
 *       handler
 *     - RoomMember.setRole / Group.setAvatar / Group.rename
 *
 *   Barriers (sender-role / sender-membership checks):
 *     - Boolean guards involving a comparison of sender_id /
 *       sender_member_id against an admin-list or member-list query
 *     - Method calls named *isAdmin / *hasPermissionToMutate /
 *       *isGroupMember / *isAuthorizedSender / *checkGroupAdminRole /
 *       *requireAdminPermission
 *     - Comparison against constants like Role.ADMIN, PowerLevel.MODERATOR
 *
 *   Configuration:
 *     The classic encoding is two-step: first, find handler methods that
 *     mutate group state (sink presence). Second, for each such handler,
 *     check whether any of the barrier predicates appears on every path
 *     from the handler entry to the mutation. Where no path-dominating
 *     barrier exists, emit a finding.
 *
 *     module GroupStateUnauthConfig implements DataFlow::ConfigSig { ... }
 *     module GroupStateUnauthFlow = TaintTracking::Global<GroupStateUnauthConfig>;
 *
 *   Select clause emits: sink, "INV-03: Group-state mutation in handler
 *     $@ proceeds without a sender-role / sender-membership barrier."
 *
 * Until this stub is fleshed out, the runner produces an empty SARIF
 * result set for INV-03. The manifest entry truthfully records
 * `expected_violations: "unknown"` for the demo fixture and real targets;
 * the ground-truth assertion lands with the full encoding at M7.
 *
 * See aegisgraph/invariants/manifest.json :: INV-03 for the canonical
 * statement, rationale, MASTG-AUTH-2 / SSDF PW.4.4 mappings.
 *
 * TODO[M7]: Fully encode this query per the spec above. Add three
 * synthetic test fixtures under tests/fixtures/demo-vulnerable-app/ that
 * exercise (a) an admin-check-present handler (negative), (b) a missing-
 * check handler (positive), and (c) a handler whose admin check happens
 * on a non-dominating branch (positive).
 * ─────────────────────────────────────────────────────────────────────
 */

import java

// Trivially-empty query so codeql syntactically accepts the file while
// the stub is in place. select clause produces no results.
from Method m
where none()
select m, "INV-03 stub — see comment block in this file for the M7 encoding plan."
