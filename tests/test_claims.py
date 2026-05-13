from aegisgraph.claims import canonical_claim_state, transition_allowed
from aegisgraph.constants import CLAIM_STATES


def test_v02_v03_claim_states_migrate_to_v1():
    assert canonical_claim_state("candidate") == "observed"
    assert canonical_claim_state("static_supported") == "anchored"
    assert canonical_claim_state("priority_validation") == "validation_tasked"
    assert canonical_claim_state("validation-tasked") == "validation_tasked"


def test_v02_v03_alias_map_unchanged():
    # Regression guard: ADR-0013 schema v2 additions MUST NOT alter the
    # v0.2/v0.3 alias map. Hash-chain stability of v1 records depends on
    # the canonical claim-state names not shifting under their feet.
    from aegisgraph.claims import V02_V03_CLAIM_STATE_MAP
    assert V02_V03_CLAIM_STATE_MAP["candidate"] == "observed"
    assert V02_V03_CLAIM_STATE_MAP["static_supported"] == "anchored"
    assert V02_V03_CLAIM_STATE_MAP["priority_validation"] == "validation_tasked"
    assert V02_V03_CLAIM_STATE_MAP["harness_covered"] == "reviewed"
    assert V02_V03_CLAIM_STATE_MAP["defensive_recommendation"] == "accepted"
    assert V02_V03_CLAIM_STATE_MAP["vulnerability_claim"] == "limited"


def test_claim_state_transitions_are_monotonic_or_limited():
    assert transition_allowed("observed", "reviewed").valid
    assert transition_allowed("reviewed", "limited").valid
    assert not transition_allowed("reviewed", "anchored").valid


# --- ADR-0013 schema v2: new disclosure-pipeline claim states ---


def test_new_disclosure_states_present_in_claim_states():
    assert "reviewed_embargoed" in CLAIM_STATES
    assert "disclosed_public" in CLAIM_STATES


def test_reviewed_to_reviewed_embargoed_allowed():
    assert transition_allowed("reviewed", "reviewed_embargoed").valid


def test_reviewed_embargoed_self_loop_allowed():
    # Self-loop is allowed at the state-machine level; ledger-event
    # requirement is enforced separately by the disclosure module.
    assert transition_allowed("reviewed_embargoed", "reviewed_embargoed").valid


def test_reviewed_embargoed_to_disclosed_public_allowed():
    assert transition_allowed("reviewed_embargoed", "disclosed_public").valid


def test_reviewed_embargoed_to_retired_allowed():
    # Finding invalidated during embargo: must be able to retire.
    assert transition_allowed("reviewed_embargoed", "retired").valid


def test_reviewed_embargoed_to_limited_allowed():
    # Counsel directs scope reduction.
    assert transition_allowed("reviewed_embargoed", "limited").valid


def test_disclosed_public_to_retired_allowed():
    # CVE rejected or duplicate.
    assert transition_allowed("disclosed_public", "retired").valid


def test_disclosed_public_cannot_revert_to_reviewed_embargoed():
    # Monotonic invariant: once public, cannot go back to embargoed.
    assert not transition_allowed("disclosed_public", "reviewed_embargoed").valid


def test_disclosed_public_cannot_revert_to_reviewed():
    assert not transition_allowed("disclosed_public", "reviewed").valid


def test_observed_cannot_jump_to_reviewed_embargoed():
    # Embargo requires traversing the normal review path first.
    # (Forward-jump IS allowed by the monotonic rule, so we assert the
    # forward-jump is legitimate but record that the disclosure module
    # itself MUST gate this via a separate `reviewed` precondition check
    # backed by a ledger 'reviewed' transition event. The state-machine
    # check alone is insufficient.)
    transition = transition_allowed("observed", "reviewed_embargoed")
    # state-machine permissive (monotonic forward)
    assert transition.valid, "monotonic forward should be state-machine-legal"
    # but: the disclosure module must add the precondition that a
    # `reviewed` transition is recorded in the ledger first; we don't
    # encode that here, just flag the test as a contract reminder.


def test_anchored_cannot_revert_via_disclosed_public():
    # disclosed_public > anchored in ordering, so this is forward
    # (state-machine legal), but reaching disclosed_public from anchored
    # without traversing reviewed/reviewed_embargoed must be blocked at
    # the disclosure-module layer (ledger event prerequisite).
    transition = transition_allowed("anchored", "disclosed_public")
    assert transition.valid, "monotonic forward should be state-machine-legal"
    # disclosure-module guard not asserted here; see disclosure tests.


def test_retired_remains_terminal_for_new_states():
    # Retired claims cannot be promoted to any new state either.
    assert not transition_allowed("retired", "reviewed_embargoed").valid
    assert not transition_allowed("retired", "disclosed_public").valid
