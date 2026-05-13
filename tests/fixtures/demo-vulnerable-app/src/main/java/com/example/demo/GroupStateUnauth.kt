// Synthetic ground-truth fixture for InvariantCheck INV-03.
// Not based on any real product code.
//
// Expected violations: 1
//   * applyGroupAddMember: GroupAddMemberEvent.getMemberId() flows into
//     GroupStateStore.addMember() without verifying sender admin role.
//
// Clean control: applyGroupAddMemberAuthorized uses verifyAdminRole barrier.
package com.example.demo

class GroupStateUnauth {

    fun applyGroupAddMember(event: GroupAddMemberEvent, state: GroupStateStore) {
        // VIOLATION 1: no sender-role verification before mutating group state.
        val newMember = event.memberId
        state.addMember(newMember)
    }

    // Clean control: authorization barrier present.
    fun applyGroupAddMemberAuthorized(event: GroupAddMemberEvent, state: GroupStateStore) {
        if (!event.verifyAdminRole()) {
            return
        }
        state.addMember(event.memberId)
    }

    class GroupAddMemberEvent {
        val memberId: String = ""
        fun verifyAdminRole(): Boolean = false
    }

    class GroupStateStore {
        fun addMember(memberId: String) {}
    }
}
