import shutil

from aegisgraph.extraction import run_extract
from aegisgraph.polydiff import run_regression
from aegisgraph.reprochain import map_targets
from aegisgraph.validation import validate_repo


def test_generated_records_validate_in_temporary_repo(tmp_path):
    shutil.copytree("schema", tmp_path / "schema")
    run_extract(tmp_path)
    map_targets(tmp_path)
    run_regression(tmp_path)

    report = validate_repo(tmp_path)

    assert report["status"] == "pass"
    assert report["records_checked"] >= 6
