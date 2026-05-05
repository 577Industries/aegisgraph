from aegisgraph.extraction import make_media_reachability_record
from aegisgraph.io import repo_root
from aegisgraph.schema import validate_evidence_record


def test_extraction_record_validates_against_v1_schema():
    record = make_media_reachability_record("signal")
    assert validate_evidence_record(record, repo_root()) == []
