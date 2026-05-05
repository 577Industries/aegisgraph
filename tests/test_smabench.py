from aegisgraph.smabench import run


def test_smabench_outputs_repeatable_corpus_hashes(tmp_path):
    first = run(tmp_path)
    second = run(tmp_path)
    first_hashes = [item["sha256"] for item in first["rings"]["ring1"]["corpora"]]
    second_hashes = [item["sha256"] for item in second["rings"]["ring1"]["corpora"]]
    assert first_hashes == second_hashes
    assert first["rings"]["ring3"]["status"] == "authorization_placeholder"
