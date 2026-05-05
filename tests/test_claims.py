from aegisgraph.claims import canonical_claim_state, transition_allowed


def test_v02_v03_claim_states_migrate_to_v1():
    assert canonical_claim_state("candidate") == "observed"
    assert canonical_claim_state("static_supported") == "anchored"
    assert canonical_claim_state("priority_validation") == "validation_tasked"
    assert canonical_claim_state("validation-tasked") == "validation_tasked"


def test_claim_state_transitions_are_monotonic_or_limited():
    assert transition_allowed("observed", "reviewed").valid
    assert transition_allowed("reviewed", "limited").valid
    assert not transition_allowed("reviewed", "anchored").valid
