from aegisgraph.polydiff import detect_disagreements, fact_vectors_for, run_regression


def test_polydiff_detects_parser_disagreement():
    vectors = fact_vectors_for("T", "https://safe.example\\@192.0.2.11/admin")
    disagreements = detect_disagreements(vectors)
    assert disagreements
    assert any(disagreement.axis == "host" for disagreement in disagreements)


def test_polydiff_regression_produces_tier_p1_records(tmp_path):
    report = run_regression(tmp_path)
    assert report["tier_p1_status"] == "pass"
    assert len(report["records"]) >= 3
