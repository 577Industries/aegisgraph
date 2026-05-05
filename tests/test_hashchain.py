from copy import deepcopy

from aegisgraph.hashchain import attach_hash_chain, verify_hash_chain


def test_hash_chain_round_trip_and_tamper_detection():
    record = {"id": "AG-EV-TEST", "value": 7}
    chained = attach_hash_chain(record)
    assert verify_hash_chain(chained) == []

    tampered = deepcopy(chained)
    tampered["value"] = 8
    assert verify_hash_chain(tampered)
